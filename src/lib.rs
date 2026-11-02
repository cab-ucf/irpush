//! irpush: one socket per device, post-quantum end-to-end encrypted push for iroh apps.
//!
//! - Devices hold one TLS/TCP relay connection; its heartbeat is learned per network by testing the
//!   *inbound* path (a host echoes after the candidate idle time).
//! - Hosts (always-on desktops) are the servers: they queue, introduce members, revoke, and post to
//!   APNs directly for iOS. Desktops listen on every candidate relay; phones never probe.
//! - Every frame is fixed-size and sealed end to end with X-Wing (ML-KEM-768 + X25519) + a pairwise
//!   PSK. Relays and Apple see ids/tokens, IPs and timing; never content, app, kind or length.
//! - One node per phone: the first app binds the local socket and runs it, later apps attach over it
//!   (`local`). iOS cannot share a socket across apps; its apps share the identity (App Group) and
//!   each has its own APNs route.
//!
//! Trust model: hosts are trusted infrastructure. Only hosts issue tickets, introduce, revoke and set
//! mesh relays. A stolen device can be revoked and cannot add members.
mod apns;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod local;
mod proto;
mod relay;
mod store;

pub use apns::Svc;
pub use local::Local;
pub use proto::{App, BODY, FRAME, app};
pub use relay::{N0, NO_N0, Relay, is_n0};
pub use store::{Role, write_private};

/// 32 random bytes from the OS (KEKs, relay tokens).
pub fn random32() -> [u8; 32] { rnd() }

use anyhow::{Context, Result, bail, ensure};
use data_encoding::BASE64;
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use iroh_base::{EndpointId, RelayUrl};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{client::{Client, ClientBuilder}, protos::relay::{ClientToRelayMsg as Out, RelayToClientMsg as In}, tls};
use proto::{Id, Kind, Rd, lp, now, rnd, tag};
use std::{collections::{HashMap, HashSet, VecDeque}, path::{Path, PathBuf}, sync::{Mutex, MutexGuard, atomic::{AtomicBool, Ordering::Relaxed}}, time::Duration};
use store::{Disk, Peer};
use tokio::{sync::{Notify, mpsc, watch}, time::{Instant, sleep, sleep_until, timeout}};
use tracing::{debug, info, warn};
use x_wing::{DecapsulationKey, kem::{Decapsulator, KeyExport}};

const TICKET_TTL: Duration = Duration::from_secs(600);
const ROTATE: u64 = 7 * 86400; // X-Wing key epoch (forward secrecy)
const PUSH_TTL: Duration = Duration::from_secs(86400);
const HB: (Duration, Duration) = (Duration::from_secs(120), Duration::from_secs(28 * 60));
const SETTLED: u32 = 1 << 31; // learned heartbeat: inbound limit found, stop probing
const MAX_PENDING: usize = 256; // per peer
const MAX_OUTBOX: usize = 256;
const MAX_DEVICE_RELAYS: usize = 4; // per device
const MAX_LISTEN: usize = 8;
const MAX_SEEN: usize = 1 << 16; // frame ids remembered for replay rejection
/// `Node::network(OFFLINE)`: no network; the device parks instead of retrying.
pub const OFFLINE: u64 = u64::MAX;

type Tx = mpsc::UnboundedSender<(EndpointId, Vec<u8>)>;

struct Secret { s: [u8; 32], grant: Role, exp: Instant, used: Option<EndpointId> } // issued by this host
struct Join { host: EndpointId, s: [u8; 32], exp: Instant }                         // ticket being redeemed
impl Drop for Secret { fn drop(&mut self) { zeroize::Zeroize::zeroize(&mut self.s) } }
impl Drop for Join { fn drop(&mut self) { zeroize::Zeroize::zeroize(&mut self.s) } }
struct Pend { to: EndpointId, app: App, data: Vec<u8>, exp: Instant, apns: bool }  // re-sealed per send

enum Opened { Peer(Vec<u8>), Issued(usize, Vec<u8>), Joined(Vec<u8>) }

struct State {
    d: Disk,
    dk: [DecapsulationKey; 2], // current, previous
    secrets: Vec<Secret>,
    join: Option<Join>,
    pending: HashMap<Id, Pend>,
    nack: HashMap<EndpointId, Instant>,       // rate limit for key-resync Hellos
    seen: HashMap<Id, Instant>,               // non-push frame ids, until they leave the freshness window
    echo_until: HashMap<EndpointId, Instant>, // host: one outstanding echo per device
    via: HashMap<EndpointId, String>,         // relay each peer was last heard on
    down: HashMap<String, (Instant, Duration)>, // device: failing relays, skip until
    net: u64,
    echoed: bool,
    echo_alive: bool,
}

impl State {
    fn new(d: Disk) -> Self {
        let dk = [DecapsulationKey::from(d.xw), DecapsulationKey::from(d.xw_prev)];
        Self { d, dk, secrets: vec![], join: None, pending: HashMap::new(), nack: HashMap::new(), seen: HashMap::new(), echo_until: HashMap::new(), via: HashMap::new(), down: HashMap::new(), net: 0, echoed: false, echo_alive: false }
    }
    fn id(&self) -> EndpointId { self.d.sk.public() }
    fn hb(&self, net: u64) -> Duration { self.d.hb.get(&net).map_or(HB.0, |s| Duration::from_secs((s & !SETTLED) as u64)) }
    fn ek(&self) -> Vec<u8> { self.dk[0].encapsulation_key().to_bytes().to_vec() }
    fn hosts(&self) -> Vec<EndpointId> { self.d.peers.iter().filter(|p| p.1.role == Role::Host).map(|p| *p.0).collect() }
    fn relays_msg(&self) -> Vec<u8> { [&self.d.relays_ver.to_le_bytes()[..], &Relay::enc(&self.d.relays)].concat() }

    /// key epoch | ek | tag(mesh relays) | device: its app's relays (hosts listen there)
    fn hello(&self) -> Vec<u8> {
        let app = if self.d.role == Role::Device { Relay::enc(&self.d.app) } else { lp(&[]) };
        [&self.d.rotated.to_le_bytes()[..], &self.ek(), &tag(&self.relays_msg()), &app].concat()
    }

    /// Device: preference order. Unpaired: only where the ticket's host listens.
    fn candidates(&self) -> Vec<Relay> {
        let app = self.d.app.iter().filter(|_| !self.hosts().is_empty()).cloned();
        let all = relay::dedup(self.d.relays.iter().cloned().chain(app).chain(relay::fallback(&self.d.relays))); // n0: the last resort
        let t = Instant::now();
        let up: Vec<_> = all.iter().filter(|r| self.down.get(&r.url).is_none_or(|d| d.0 <= t)).cloned().collect();
        if up.is_empty() { all } else { up }
    }

    /// Host: everywhere a member might be.
    fn listen(&self) -> Vec<Relay> {
        let devices = self.d.peers.values().filter(|p| p.role == Role::Device).flat_map(|p| p.relays.iter().cloned());
        let mut l = relay::dedup(self.d.relays.iter().cloned().chain(devices));
        l.truncate(MAX_LISTEN);
        relay::dedup(l.into_iter().chain(relay::fallback(&self.d.relays)))
    }

    fn frame(&self, to: EndpointId, kind: Kind, id: &Id, app: &App, data: &[u8]) -> Result<Vec<u8>> {
        let p = self.d.peers.get(&to).context("unknown peer")?;
        Ok(proto::seal(&p.psk, Some(&p.ek), self.id(), to, &proto::plain(kind, id, app, data)?))
    }

    fn open(&self, from: EndpointId, f: &[u8]) -> Option<Opened> {
        let me = self.id();
        if let Some(p) = self.d.peers.get(&from) {
            let psk_hello = || proto::open_psk(&p.psk, from, me, f).filter(|pt| pt[0] == Kind::Hello as u8); // key resync only
            if let Some(pt) = proto::open_kem(&self.dk, &p.psk, from, me, f).or_else(psk_hello) { return Some(Opened::Peer(pt)) }
        } // else (or not decryptable): a pairing retry from a just-paired peer is still answered
        let t = Instant::now();
        if let Some(j) = self.join.as_ref().filter(|j| j.host == from && j.exp > t) {
            return proto::open_psk(&j.s, from, me, f).map(Opened::Joined);
        }
        self.secrets.iter().enumerate().filter(|(_, s)| s.exp > t && s.used.is_none_or(|u| u == from))
            .find_map(|(i, s)| proto::open_psk(&s.s, from, me, f).map(|pt| Opened::Issued(i, pt)))
    }
}

pub struct Node {
    st: Mutex<State>,
    path: PathBuf,
    kek: [u8; 32],
    sessions: Mutex<HashMap<String, Tx>>,          // live relay connections
    outbox: Mutex<VecDeque<(EndpointId, Vec<u8>)>>, // frames made while no relay is connected
    atx: mpsc::UnboundedSender<(Id, bool)>,         // APNs fallback: (push id, wait for relay ack)
    arx: Mutex<Option<mpsc::UnboundedReceiver<(Id, bool)>>>,
    kick: Notify,
    reset: Notify,
    changed: Notify,
    paused: AtomicBool,
    relay: watch::Sender<Option<String>>, // relay in use (device), for "using the n0 fallback" notices
}

/// iOS Notification Service Extension: decrypt an APNs payload's `f` field with the app's state,
/// read-only, on the phone. `None`: not ours, not a push, or already delivered.
pub fn open_notification(path: &Path, kek: &[u8; 32], f_b64: &str) -> Result<Option<(EndpointId, App, Vec<u8>)>> {
    let (st, f) = (State::new(store::load(path, kek)?), BASE64.decode(f_b64.as_bytes())?);
    for from in st.d.peers.keys() { // the payload names no sender (Apple never learns it): try each peer
        if let Some(pt) = proto::open_kem(&st.dk, &st.d.peers[from].psk, *from, st.id(), &f) {
            let m = proto::parse(&pt)?;
            return Ok((m.kind == Kind::Push && store::first_delivery(path, &m.id)?).then(|| (*from, m.app, m.data.to_vec())));
        }
    }
    Ok(None)
}

impl Node {
    /// Found a new mesh; this node is its first host. `relays`: your own (preferred), may be empty.
    pub fn create(path: impl Into<PathBuf>, kek: [u8; 32], relays: Vec<Relay>) -> Result<Self> {
        let path = path.into();
        ensure!(!path.exists(), "{} exists: refusing to replace an identity", path.display());
        let mut d = Disk::new(Role::Host, relays, vec![]);
        d.relays_ver = now();
        Self::boot(path, kek, d)
    }

    /// Join with a one-time ticket. Pairing completes (and is retried) once `run` reaches a relay.
    /// `app`: the app developer's default relays; used after the mesh's own.
    pub fn join(path: impl Into<PathBuf>, kek: [u8; 32], ticket: &str, app: Vec<Relay>) -> Result<Self> {
        let (h, relays) = ticket.trim().strip_prefix("irpush5:").and_then(|t| t.split_once('@')).context("bad ticket")?;
        let b = hex::decode(h)?;
        let mut r = Rd(&b);
        let (host, s, role) = (r.id()?, r.arr()?, Role::of(r.u8()?));
        ensure!(r.0.is_empty(), "bad ticket");
        let path = path.into();
        ensure!(!path.exists(), "{} exists: refusing to replace an identity", path.display());
        let n = Self::boot(path, kek, Disk::new(role, Relay::list(relays)?, app))?;
        n.lock().join = Some(Join { host, s, exp: Instant::now() + TICKET_TTL });
        Ok(n)
    }

    /// Every later start. Devices pass their app's current default relays (updates may change them).
    pub fn open(path: impl Into<PathBuf>, kek: [u8; 32], app: Vec<Relay>) -> Result<Self> {
        let path = path.into();
        let mut d = store::load(&path, &kek)?;
        if d.role == Role::Device { d.app = app; }
        Self::boot(path, kek, d)
    }

    fn boot(path: PathBuf, kek: [u8; 32], d: Disk) -> Result<Self> {
        let (atx, arx) = mpsc::unbounded_channel();
        let n = Self { st: Mutex::new(State::new(d)), path, kek, sessions: Mutex::default(), outbox: Mutex::default(), atx, arx: Mutex::new(Some(arx)),
            kick: Notify::new(), reset: Notify::new(), changed: Notify::new(), paused: AtomicBool::new(false), relay: watch::channel(None).0 };
        n.save(&n.lock())?;
        Ok(n)
    }

    fn lock(&self) -> MutexGuard<'_, State> { self.st.lock().unwrap_or_else(|e| e.into_inner()) }
    fn save(&self, st: &State) -> Result<()> { store::save(&self.path, &self.kek, &st.d) }

    pub fn id(&self) -> EndpointId { self.lock().id() }
    pub fn role(&self) -> Role { self.lock().d.role }
    pub fn peers(&self) -> Vec<(EndpointId, Role)> { self.lock().d.peers.iter().map(|(i, p)| (*i, p.role)).collect() }
    pub fn relays(&self) -> Vec<Relay> { self.lock().d.relays.clone() }

    /// The relay this device is connected through (None: offline). Apps can show a notice while it is
    /// n0's public fallback (`relay::is_n0`): still end-to-end encrypted, n0 sees ids, IPs and timing.
    pub fn relay_watch(&self) -> watch::Receiver<Option<String>> { self.relay.subscribe() }

    /// Queue a push (<= BODY bytes) until acked, for up to 24 h. iOS peers: relay if connected,
    /// else straight to APNs.
    pub fn push(&self, to: EndpointId, app: &App, data: &[u8]) -> Result<()> {
        let (id, mut st) = (rnd(), self.lock());
        let f = st.frame(to, Kind::Push, &id, app, data)?;
        self.out(&st, to, f);
        if !st.d.apns.is_empty() && apns::parse_route(&st.d.peers[&to].route, app).is_ok() { let _ = self.atx.send((id, st.via.contains_key(&to))); }
        if st.pending.values().filter(|p| p.to == to).count() >= MAX_PENDING { // drop the oldest for this peer
            if let Some(old) = st.pending.iter().filter(|p| p.1.to == to).min_by_key(|p| p.1.exp).map(|p| *p.0) { st.pending.remove(&old); }
        }
        st.pending.insert(id, Pend { to, app: *app, data: data.to_vec(), exp: Instant::now() + PUSH_TTL, apns: false });
        Ok(())
    }

    /// iOS device: register or refresh one app's APNs token (`topic` = its bundle id; several apps
    /// share the device). Announced to hosts, sealed.
    pub fn set_route(&self, svc: Svc, topic: &str, token: &[u8]) -> Result<()> {
        let e = apns::route(svc, topic, token)?;
        let mut st = self.lock();
        let r = apns::merge(&st.d.route, &e);
        if st.d.route == r { return Ok(()) }
        st.d.route = r;
        self.save(&st)?;
        self.send_routes(&st)
    }

    fn send_routes(&self, st: &State) -> Result<()> {
        if !st.d.route.is_empty() { for h in st.hosts() { self.send(st, h, Kind::Route, &st.d.route)?; } }
        Ok(())
    }

    /// Host: your Apple team's APNs auth key (.p8); one key covers all your apps.
    pub fn set_apns_key(&self, key_id: &str, team_id: &str, p8_pem: &str) -> Result<()> {
        let creds = format!("{key_id} {team_id}\n{p8_pem}");
        apns::jwt(&creds)?; // validate now
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts send to APNs");
        st.d.apns = creds.into_bytes();
        self.save(&st)
    }

    /// One-time ticket, valid 10 minutes (QR code or in-band). Hosts only. Treat it as a secret.
    pub fn ticket(&self, grant: Role) -> Result<String> {
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts issue tickets");
        let (s, t) = (rnd(), Instant::now());
        st.secrets.retain(|x| x.exp > t);
        st.secrets.push(Secret { s, grant, exp: t + TICKET_TTL, used: None });
        Ok(format!("irpush5:{}@{}", hex::encode([&st.id().as_bytes()[..], &s, &[grant as u8]].concat()), Relay::show(&st.d.relays)))
    }

    /// Remove a member everywhere (flooded host to host; accepted only from hosts).
    pub fn revoke(&self, id: EndpointId) -> Result<()> {
        ensure!(self.role() == Role::Host, "only hosts revoke");
        self.apply_revoke(id)
    }

    /// Set the mesh's own relays (preference order, tokens included). Sent sealed to every member;
    /// offline ones get it on their next Hello; devices switch on their next connect. Also token rotation.
    pub fn set_relays(&self, l: Vec<Relay>) -> Result<()> {
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts set the mesh relays");
        (st.d.relays, st.d.relays_ver) = (l, now().max(st.d.relays_ver + 1));
        self.save(&st)?;
        for p in st.d.peers.keys() { self.send(&st, *p, Kind::Relays, &st.relays_msg())?; }
        self.changed.notify_one();
        Ok(())
    }

    /// Android: ConnectivityManager.NetworkCallback; iOS: NWPathMonitor (any stable id per network).
    /// `OFFLINE` when there is no network: the device parks until the next call.
    pub fn network(&self, id: u64) { self.lock().net = id; self.reset.notify_waiters(); }
    /// Android: from an AlarmManager alarm (in-process timers stall during suspend): heartbeat now.
    /// Returns when to call again: this network's learned heartbeat.
    pub fn kick(&self) -> Duration {
        self.kick.notify_one();
        let st = self.lock();
        st.hb(st.net)
    }
    /// iOS: true when backgrounded, so hosts switch to APNs immediately.
    pub fn pause(&self, p: bool) { self.paused.store(p, Relaxed); self.reset.notify_waiters(); }

    fn apply_revoke(&self, id: EndpointId) -> Result<()> {
        let mut st = self.lock();
        if st.d.revoked.contains(&id) || id == st.id() { return Ok(()) }
        st.d.revoked.push(id);
        st.d.peers.remove(&id);
        st.pending.retain(|_, p| p.to != id);
        self.save(&st)?;
        if st.d.role == Role::Host { for p in st.d.peers.keys() { self.send(&st, *p, Kind::Revoke, id.as_bytes())?; } }
        self.changed.notify_one(); // its relays leave the listen set
        Ok(())
    }

    fn send(&self, st: &State, to: EndpointId, kind: Kind, data: &[u8]) -> Result<()> {
        self.out(st, to, st.frame(to, kind, &rnd(), &[0; 16], data)?);
        Ok(())
    }

    /// Route a frame to the relay the peer was last heard on; unknown: every live relay; none: outbox.
    fn out(&self, st: &State, to: EndpointId, f: Vec<u8>) {
        let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match st.via.get(&to).and_then(|u| s.get(u)) {
            Some(tx) => { let _ = tx.send((to, f)); }
            None if s.is_empty() => {
                let mut o = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
                if o.len() >= MAX_OUTBOX { o.pop_front(); }
                o.push_back((to, f));
            }
            None => for tx in s.values() { let _ = tx.send((to, f.clone())); },
        }
    }

    fn handle(&self, url: &str, from: EndpointId, f: &[u8], on: &impl Fn(EndpointId, App, &[u8])) -> Result<()> {
        let mut st = self.lock();
        let Some(opened) = st.open(from, f) else {
            // A known peer we cannot decrypt holds a stale key of ours: resync (PSK mode), rate-limited.
            let t = Instant::now();
            if let Some(p) = st.d.peers.get(&from).filter(|_| st.nack.get(&from).is_none_or(|x| t > *x)) {
                let f = proto::seal(&p.psk, None, st.id(), from, &proto::plain(Kind::Hello, &rnd(), &[0; 16], &st.hello())?);
                st.nack.insert(from, t + Duration::from_secs(60));
                self.out(&st, from, f);
            }
            return Ok(());
        };
        st.via.insert(from, url.to_string());
        match opened {
            Opened::Issued(i, pt) => self.on_pair_request(&mut st, i, from, &pt),
            Opened::Joined(pt) => self.on_pair_reply(&mut st, from, &pt),
            Opened::Peer(pt) => {
                let m = proto::parse(&pt)?;
                // Replay: pushes are de-duplicated by the delivered-id log; every other kind here
                // (a relay may resend any frame inside the freshness window).
                if m.kind != Kind::Push {
                    let t = Instant::now();
                    if st.seen.len() >= MAX_SEEN { st.seen.retain(|_, x| *x > t); }
                    if st.seen.insert(m.id, t + Duration::from_secs(proto::MAX_AGE + proto::MAX_SKEW)).is_some_and(|x| x > t) { return Ok(()) }
                }
                let host = st.d.peers.get(&from).is_some_and(|p| p.role == Role::Host);
                let mut r = Rd(m.data);
                match m.kind {
                    Kind::Push => {
                        self.out(&st, from, st.frame(from, Kind::Ack, &rnd(), &m.id, &[])?); // app field carries the acked id
                        drop(st);
                        if store::first_delivery(&self.path, &m.id)? { on(from, m.app, m.data); } // else retransmit / iOS extension had it
                    }
                    Kind::Ack => { st.pending.remove(&m.app); }
                    Kind::Hello => self.on_hello(&mut st, from, &mut r)?,
                    Kind::Intro if host => {
                        let (id, role, ek, psk) = (r.id()?, Role::of(r.u8()?), r.ek()?, r.arr()?);
                        let met = role == Role::Host || st.d.role == Role::Host; // devices never take devices
                        if met && id != st.id() && !st.d.revoked.contains(&id) && !st.d.peers.contains_key(&id) {
                            st.d.peers.insert(id, Peer { ek, psk, role, ts: 0, route: vec![], relays: vec![] });
                            self.save(&st)?;
                            self.send(&st, id, Kind::Hello, &st.hello())?;
                        }
                    }
                    Kind::Revoke if host => { let id = r.id()?; drop(st); self.apply_revoke(id)?; }
                    Kind::Relays if host => {
                        let (ver, l) = (r.u64()?, Relay::dec(&mut r)?);
                        if ver > st.d.relays_ver { (st.d.relays, st.d.relays_ver) = (l, ver); self.save(&st)?; self.changed.notify_one(); }
                    }
                    Kind::Echo if st.d.role == Role::Host && m.data.len() == 4 => self.on_echo_request(&mut st, from, &mut r)?,
                    Kind::Echo if host => if m.data.is_empty() { st.echoed = true } else { st.echo_alive = true },
                    Kind::Route if st.d.role == Role::Host && !host && apns::valid(m.data) => {
                        let changed = st.d.peers.get_mut(&from).filter(|p| p.route != m.data).map(|p| p.route = m.data.to_vec()).is_some();
                        if changed { self.save(&st)?; }
                    }
                    k => debug!(?k, %from, "ignored"),
                }
                Ok(())
            }
        }
    }

    /// Host: a ticket holder pairs. Idempotent per secret, so the joiner can retry until it hears back.
    fn on_pair_request(&self, st: &mut State, i: usize, from: EndpointId, pt: &[u8]) -> Result<()> {
        let m = proto::parse(pt)?;
        ensure!(m.kind == Kind::Pair, "expected pair");
        let (s, grant, first) = (st.secrets[i].s, st.secrets[i].grant, st.secrets[i].used.is_none());
        if first {
            let mut r = Rd(m.data);
            let ek = r.ek()?;
            let relays = if grant == Role::Device { device_relays(Relay::dec(&mut r).unwrap_or_default()) } else { vec![] };
            st.secrets[i].used = Some(from);
            st.d.peers.insert(from, Peer { ek, psk: proto::pair_psk(&s, st.id(), from), role: grant, ts: 0, route: vec![], relays });
            self.save(st)?;
            self.changed.notify_one();
            info!(%from, ?grant, "paired");
        }
        // Reply first (the joiner must know us before our introductions arrive). Retries repeat both;
        // introductions are idempotent (deterministic PSK), so a lost frame never splits a pair.
        let reply = proto::plain(Kind::Pair, &rnd(), &[0; 16], &[&[st.d.role as u8][..], &st.ek()].concat())?;
        self.out(st, from, proto::seal(&s, None, st.id(), from, &reply));
        // Devices meet hosts only: a host may serve many people's phones without telling one of another.
        let others: Vec<_> = st.d.peers.iter().filter(|p| *p.0 != from && (grant == Role::Host || p.1.role == Role::Host)).map(|p| *p.0).collect();
        for o in others { self.introduce(st, from, o)?; }
        Ok(())
    }

    /// Joiner: (re)send the pairing request, sealed with the ticket secret.
    fn pair_request(&self, st: &State) -> Result<()> {
        let Some(j) = st.join.as_ref().filter(|j| j.exp > Instant::now()) else { return Ok(()) };
        let pt = proto::plain(Kind::Pair, &rnd(), &[0; 16], &[st.ek(), Relay::enc(&st.d.app)].concat())?;
        self.out(st, j.host, proto::seal(&j.s, None, st.id(), j.host, &pt));
        Ok(())
    }

    /// Joiner: the ticket's host answered.
    fn on_pair_reply(&self, st: &mut State, from: EndpointId, pt: &[u8]) -> Result<()> {
        let m = proto::parse(pt)?;
        ensure!(m.kind == Kind::Pair, "expected pair");
        let s = st.join.take().context("no join")?.s;
        let mut r = Rd(m.data);
        let (role, ek) = (Role::of(r.u8()?), r.ek()?);
        st.d.peers.insert(from, Peer { ek, psk: proto::pair_psk(&s, st.id(), from), role, ts: 0, route: vec![], relays: vec![] });
        self.save(st)?;
        if role == Role::Host { self.send(st, from, Kind::Hello, &st.hello())?; }
        info!(%from, "joined");
        Ok(())
    }

    /// A peer is online, maybe with a rotated key, new APNs token or new app relays.
    fn on_hello(&self, st: &mut State, from: EndpointId, r: &mut Rd) -> Result<()> {
        let (ts, ek, tg) = (r.u64()?, r.ek()?, r.arr::<8>()?);
        let relays = Relay::dec(r).unwrap_or_default();
        let me_host = st.d.role == Role::Host;
        let p = st.d.peers.get_mut(&from).context("peer")?;
        let rekey = ts >= p.ts && ek != p.ek;
        let relays = if me_host && p.role == Role::Device { device_relays(relays) } else { p.relays.clone() };
        let relays_changed = relays != p.relays;
        if rekey { (p.ek, p.ts) = (ek, ts); }
        p.relays = relays;
        if rekey || relays_changed { self.save(st)?; }
        if relays_changed { self.changed.notify_one(); }
        if rekey { self.send(st, from, Kind::Hello, &st.hello())?; } // answer with ours once
        if me_host && tg != tag(&st.relays_msg()) { self.send(st, from, Kind::Relays, &st.relays_msg())?; } // missed an update
        self.flush(st, Some(from));
        Ok(())
    }

    /// Host: "reach me after N s of silence" (tests the device's inbound path). One per device at a time.
    fn on_echo_request(&self, st: &mut State, from: EndpointId, r: &mut Rd) -> Result<()> {
        let d = Duration::from_secs((r.u32()? as u64).min(HB.1.as_secs()));
        let t = Instant::now();
        if st.echo_until.get(&from).is_some_and(|u| *u > t) { return Ok(()) }
        st.echo_until.insert(from, t + d + Duration::from_secs(60));
        self.send(st, from, Kind::Echo, &[0])?; // "alive": a missing echo then means the path, not us
        let f = st.frame(from, Kind::Echo, &rnd(), &[0; 16], &[])?;
        let tx = st.via.get(&from).and_then(|u| self.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(u).cloned());
        if let Some(tx) = tx { tokio::spawn(async move { sleep(d).await; let _ = tx.send((from, f)); }); }
        Ok(())
    }

    /// Host: pairwise PSK for a and b, derived from our introduction secret so re-sending is idempotent.
    fn introduce(&self, st: &State, a: EndpointId, b: EndpointId) -> Result<()> {
        let psk = proto::intro_psk(&st.d.intro, a, b);
        let card = |x: EndpointId| -> Result<Vec<u8>> { let p = st.d.peers.get(&x).context("peer")?; Ok([&x.as_bytes()[..], &[p.role as u8], &p.ek.to_bytes(), &psk].concat()) };
        self.send(st, b, Kind::Intro, &card(a)?)?;
        self.send(st, a, Kind::Intro, &card(b)?)
    }

    fn flush(&self, st: &mut State, only: Option<EndpointId>) {
        let t = Instant::now();
        st.pending.retain(|_, p| p.exp > t);
        for (id, p) in st.pending.iter().filter(|p| only.is_none_or(|o| o == p.1.to)) {
            if let Ok(f) = st.frame(p.to, Kind::Push, id, &p.app, &p.data) { self.out(st, p.to, f); }
        }
    }

    /// Weekly X-Wing key rotation, announced via Hello. Frames sealed to the previous key still open.
    fn rotate(&self, st: &mut State) -> Result<()> {
        if now() < st.d.rotated + ROTATE { return Ok(()) }
        (st.d.xw_prev, st.d.xw, st.d.rotated) = (st.d.xw, rnd(), now());
        st.dk = [DecapsulationKey::from(st.d.xw), DecapsulationKey::from(st.d.xw_prev)];
        self.save(st)?;
        for p in st.d.peers.keys() { self.send(st, *p, Kind::Hello, &st.hello())?; }
        Ok(())
    }

    /// Run forever; `on(sender, app, data)` fires once per push (wrap it with [`Local::deliver`] when
    /// serving other apps on this machine). Device: one relay connection. Host: one listener per
    /// candidate relay, plus the APNs sender.
    pub async fn run(&self, on: impl Fn(EndpointId, App, &[u8])) -> Result<()> {
        let arx = self.arx.lock().unwrap_or_else(|e| e.into_inner()).take().context("run called twice")?;
        let tlsc = tls::CaTlsConfig::default().client_config(pq())?; // shared: TLS resumption
        let dns = DnsResolver::new();                                                    // shared: DNS cache
        let relays = async {
            if self.role() == Role::Device { return self.relay_loop(None, &tlsc, &dns, &on).await }
            let (mut loops, mut running) = (FuturesUnordered::new(), HashSet::new());
            loop {
                let want = self.lock().listen();
                for r in want { if running.insert(r.url.clone()) { loops.push(self.relay_loop(Some(r.url), &tlsc, &dns, &on)) } }
                tokio::select! { Some(u) = loops.next() => { running.remove(&u); }, _ = self.changed.notified() => {} }
            }
        };
        tokio::join!(relays, self.apns_loop(arx, tlsc.clone()));
        Ok(())
    }

    /// `fixed`: host listener for one relay (returns when it leaves the set). None: device, walks the
    /// candidates in preference order on every reconnect; a failing relay is skipped with backoff.
    async fn relay_loop(&self, fixed: Option<String>, tlsc: &rustls::ClientConfig, dns: &DnsResolver, on: &impl Fn(EndpointId, App, &[u8])) -> String {
        let mut backoff = Duration::from_millis(250);
        let idle = || self.paused.load(Relaxed) || (fixed.is_none() && self.lock().net == OFFLINE);
        loop {
            loop { // paused or offline: no radio use until the platform says otherwise
                let w = self.reset.notified();
                tokio::pin!(w);
                w.as_mut().enable(); // registered before the check: no missed wakeup
                if !idle() { break }
                w.await;
            }
            let (cands, sk) = {
                let st = self.lock();
                let c = match &fixed { Some(u) => st.listen().into_iter().filter(|r| &r.url == u).collect(), None => st.candidates() };
                (c, st.d.sk.clone())
            };
            if cands.is_empty() { return fixed.unwrap_or_default() }
            for r in cands {
                let Ok(url) = r.url.parse::<RelayUrl>() else { continue };
                let mut b = ClientBuilder::new(url, sk.clone(), dns.clone()).tls_client_config(tlsc.clone());
                if let Some(t) = r.token { b = b.auth_token(hex::encode(t)); }
                match timeout(Duration::from_secs(8), b.connect()).await {
                    Ok(Ok(c)) => {
                        self.lock().down.remove(&r.url);
                        backoff = Duration::from_millis(250);
                        if let Err(e) = self.session(c, &r.url, on).await { info!(relay = %r.url, "session ended: {e:#}") }
                        break;
                    }
                    e => {
                        warn!(relay = %r.url, "connect failed: {}", e.map_or("timeout".into(), |e| e.err().map(|e| e.to_string()).unwrap_or_default()));
                        if fixed.is_none() {
                            let mut st = self.lock();
                            let d = st.down.get(&r.url).map_or(Duration::from_secs(300), |d| (d.1 * 2).min(Duration::from_secs(6 * 3600)));
                            st.down.insert(r.url.clone(), (Instant::now() + d, d));
                        }
                    }
                }
            }
            if idle() { continue }
            tokio::select! { _ = sleep(backoff) => {}, _ = self.kick.notified() => {}, _ = self.reset.notified() => {} }
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
    }

    async fn session(&self, mut c: Client, url: &str, on: &impl Fn(EndpointId, App, &[u8])) -> Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        for m in self.outbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..) { let _ = tx.send(m); }
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(url.to_string(), tx);
        if self.role() == Role::Device {
            if relay::is_n0(url) { warn!("using n0's public relay as fallback (end-to-end encrypted; n0 sees ids, IPs, timing)") }
            self.relay.send_replace(Some(url.to_string()));
        }
        let r = self.session_inner(&mut c, url, &mut rx, on).await;
        if self.role() == Role::Device { self.relay.send_replace(None); }
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(url);
        self.lock().via.retain(|_, u| u != url);
        r
    }

    async fn session_inner(&self, c: &mut Client, url: &str, rx: &mut mpsc::UnboundedReceiver<(EndpointId, Vec<u8>)>, on: &impl Fn(EndpointId, App, &[u8])) -> Result<()> {
        // Registered once, before anything else: `notify_waiters` stores no permit, so a fresh
        // future per loop pass would miss a network change or pause arriving mid-frame.
        let reset = self.reset.notified();
        tokio::pin!(reset);
        reset.as_mut().enable();
        if self.paused.load(Relaxed) || (self.role() == Role::Device && self.lock().net == OFFLINE) { bail!("paused or offline") } // changed while connecting
        let net = {
            let mut st = self.lock();
            self.rotate(&mut st)?;
            self.pair_request(&st)?;
            for h in st.hosts() { self.send(&st, h, Kind::Hello, &st.hello())?; } // "I'm back": hosts flush queues
            if st.d.role == Role::Device { self.send_routes(&st)?; }
            self.flush(&mut st, None);
            st.net
        };
        // Heartbeat learning tests the INBOUND path: a host echoes after the candidate idle time.
        // Outbound pings alone pass behind NATs/VPNs (e.g. WireGuard without PersistentKeepalive)
        // whose mapping still accepts our ping but already drops unsolicited inbound pushes.
        let hb = |st: &State| st.hb(net);
        let settled = |st: &State| st.d.hb.get(&net).is_some_and(|s| s & SETTLED != 0);
        let learn = |st: &mut State, h: Duration, done: bool| -> Result<()> {
            let v = h.as_secs() as u32 | if done { SETTLED } else { 0 };
            if st.d.hb.insert(net, v) != Some(v) { self.save(st)?; }
            Ok(())
        };
        let probe_start = |st: &mut State| -> Result<Option<(Instant, Duration)>> {
            let (h, host) = (hb(st), st.hosts().first().copied());
            let Some(host) = host.filter(|_| st.d.role == Role::Device && !settled(st) && h < HB.1) else { return Ok(None) };
            let c = (h * 2).min(HB.1);
            (st.echoed, st.echo_alive) = (false, false);
            self.send(st, host, Kind::Echo, &(c.as_secs() as u32).to_le_bytes())?;
            Ok(Some((Instant::now() + c + Duration::from_secs(20), c)))
        };
        let mut probe = probe_start(&mut self.lock())?;
        let mut retry = Instant::now() + Duration::from_secs(5); // pairing retries, only while joining
        let (mut ping, mut due) = (None, probe.map_or(Instant::now() + hb(&self.lock()), |p| p.0));
        loop {
            tokio::select! {
                m = c.next() => match m.context("closed")?? {
                    In::Datagrams { remote_endpoint_id, datagrams } => {
                        if let Err(e) = self.handle(url, remote_endpoint_id, &datagrams.contents, on) { debug!(from = %remote_endpoint_id, "dropped frame: {e:#}") }
                        let mut st = self.lock();
                        if let Some((_, c)) = probe.filter(|_| st.echoed) { // inbound survived c of silence: adopt, try double
                            learn(&mut st, c, c >= HB.1)?;
                            probe = probe_start(&mut st)?;
                        }
                        if ping.is_none() { due = probe.map_or(Instant::now() + hb(&st), |p| p.0); } // traffic proves liveness
                    }
                    In::EndpointGone(id) => { self.lock().via.retain(|p, u| !(*p == id && u == url)); }
                    In::Ping(d) => c.send(Out::Pong(d)).await?,
                    In::Pong(d) if Some(d) == ping => (ping, due) = (None, Instant::now() + hb(&self.lock())),
                    _ => {}
                },
                Some((to, f)) = rx.recv() => c.send(Out::Datagrams { dst_endpoint_id: to, datagrams: f.into() }).await?,
                _ = sleep_until(due) => {
                    { // no lock may live across an await (keeps run() Send)
                        let mut st = self.lock();
                        if probe.take().is_some() {
                            if st.echo_alive { // host alive, echo lost: inbound dies before 2x. Keep current, stop probing.
                                let h = hb(&st);
                                learn(&mut st, h, true)?;
                                bail!("inbound idle limit found");
                            }
                            due = Instant::now(); // host never answered: inconclusive, retry next session
                            continue;
                        }
                        if ping.is_some() { // mapping died: shorten this network's heartbeat, reconnect now
                            let h = (hb(&st) / 2).max(HB.0);
                            learn(&mut st, h, true)?;
                            bail!("pong timeout");
                        }
                        if st.d.role == Role::Device && st.candidates().first().is_some_and(|r| r.url != url) {
                            bail!("moving to preferred relay"); // radio is awake anyway: no extra wakeup
                        }
                        self.rotate(&mut st)?;
                    }
                    let d = rnd();
                    c.send(Out::Ping(d)).await?;
                    (ping, due) = (Some(d), Instant::now() + Duration::from_secs(15));
                }
                _ = sleep_until(retry), if self.lock().join.is_some() => {
                    let st = self.lock();
                    if st.join.as_ref().is_some_and(|j| j.exp <= Instant::now()) { bail!("ticket expired before the host answered") }
                    self.pair_request(&st)?;
                    retry = Instant::now() + Duration::from_secs(5);
                }
                _ = self.kick.notified() => if probe.is_none() { due = Instant::now() },
                _ = &mut reset => bail!("reconnect (network change or pause)"),
            }
        }
    }

    /// Hosts post to APNs directly. `wait`: the peer looked connected; give the relay 1 s to deliver.
    async fn apns_loop(&self, mut arx: mpsc::UnboundedReceiver<(Id, bool)>, mut tlsc: rustls::ClientConfig) {
        tlsc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let http = match reqwest::Client::builder().tls_backend_preconfigured(tlsc).build() { Ok(h) => h, Err(e) => return warn!("apns client: {e}") };
        let token = Mutex::new((String::new(), 0u64)); // JWT, reused 40 min
        let one = |id: Id, wait: bool| { let (http, token) = (&http, &token); async move {
            if wait { sleep(Duration::from_secs(1)).await; }
            let (to, app, route, f, auth) = {
                let mut st = self.lock();
                let Some(p) = st.pending.get(&id).filter(|p| !p.apns) else { return Ok(()) }; // acked meanwhile
                let (to, app, data) = (p.to, p.app, p.data.clone());
                let route = apns::parse_route(&st.d.peers.get(&to).context("peer")?.route, &app)?;
                let f = BASE64.encode(&st.frame(to, Kind::Push, &id, &app, &data)?);
                let mut t = token.lock().unwrap_or_else(|e| e.into_inner());
                if now() > t.1 + 2400 { *t = (apns::jwt(std::str::from_utf8(&st.d.apns)?)?, now()); }
                if let Some(p) = st.pending.get_mut(&id) { p.apns = true; }
                (to, app, route, f, t.0.clone())
            };
            if let apns::Sent::Gone = apns::post(http, &route, &auth, &f).await? { // token dead: stop using it
                let mut st = self.lock();
                if let Some(p) = st.d.peers.get_mut(&to) { p.route = apns::remove(&p.route, &app); }
                self.save(&st)?;
            }
            anyhow::Ok(())
        }};
        let mut inflight = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some((id, wait)) = arx.recv() => inflight.push(one(id, wait)),
                Some(r) = inflight.next() => if let Err(e) = r { warn!("apns: {e:#}") },
                else => return,
            }
        }
    }
}

/// aws-lc-rs, X25519MLKEM768 first. Never iroh-relay's `default_provider`: it is ring (classical)
/// whenever the embedding app's iroh enables `tls-ring`, as iroh's defaults do.
fn pq() -> std::sync::Arc<rustls::crypto::CryptoProvider> { rustls::crypto::aws_lc_rs::default_provider().into() }

/// Relays a device may make hosts dial: public https names only, a few per device.
fn device_relays(l: Vec<Relay>) -> Vec<Relay> {
    l.into_iter().filter(|r| r.public().is_ok()).take(MAX_DEVICE_RELAYS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_hop_is_post_quantum_in_any_embedding() {
        assert_eq!(pq().kx_groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn n0_is_always_the_last_resort() {
        let mut d = Disk::new(Role::Device, Relay::list("https://mesh.example/").unwrap(), Relay::list("https://app.example/").unwrap());
        let st = State::new(Disk::new(Role::Device, d.relays.clone(), vec![]));
        assert_eq!(st.candidates().iter().map(|r| r.url.as_str()).collect::<Vec<_>>(), ["https://mesh.example/", N0]);
        d.role = Role::Host;
        assert_eq!(State::new(d).listen().last().unwrap().url, N0);
        // `!n0` in the mesh relays: no fallback anywhere in the mesh
        let own = Disk::new(Role::Device, Relay::list("https://mesh.example/,!n0").unwrap(), vec![]);
        assert!(State::new(own).candidates().iter().all(|r| r.url != N0));
    }
}
