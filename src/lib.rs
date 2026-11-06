//! irpush: one socket per device, post-quantum end-to-end encrypted push for
//! iroh apps.
//!
//! - Devices hold one TLS/TCP relay connection; its heartbeat is learned per
//!   network by testing the *inbound* path (a host echoes after the candidate
//!   idle time).
//! - Hosts (always-on desktops) are the servers: they queue, introduce members,
//!   revoke, and post to APNs directly for iOS. Desktops listen on every
//!   candidate relay; phones never probe.
//! - Every frame is fixed-size and sealed end to end with X-Wing (ML-KEM-768 +
//!   X25519) + a pairwise PSK. Relays and Apple see ids (Apple: tokens), IPs
//!   and timing; never content, app, kind or length.
//! - One node per phone: the first app binds the local socket and runs it,
//!   later apps attach over it (`local`). iOS cannot share a socket across
//!   apps; its apps share the identity (App Group) and each has its own APNs
//!   route.
//!
//! Trust model: hosts are trusted infrastructure. Only hosts issue tickets,
//! introduce, revoke and set mesh relays. A stolen device can be revoked and
//! cannot add members.
mod apns;
#[cfg(all(feature = "ffi", unix))]
pub mod ffi;
#[cfg(feature = "jni")]
mod jni;
#[cfg(unix)] // a Unix socket: desktops and one app's processes
pub mod local;
mod proto;
mod relay;
mod store;

pub use apns::Svc;
#[cfg(unix)]
pub use local::Local;
pub use proto::{App, BODY, FRAME, app};
pub use relay::{N0, NO_N0, Relay, is_n0};
pub use store::{Role, write_private};

/// 32 random bytes from the OS (KEKs).
pub fn random32() -> [u8; 32] {
    rnd()
}

use anyhow::{Context, Result, bail, ensure};
use data_encoding::BASE64;
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use iroh_base::{EndpointId, RelayUrl};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder},
    protos::relay::{ClientToRelayMsg as Out, RelayToClientMsg as In},
    tls,
};
use proto::{Id, Kind, Rd, lp, now, rnd, tag};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use store::{Disk, Mix, Peer};
use tokio::{
    sync::{Notify, mpsc, watch},
    time::{Instant, sleep, sleep_until, timeout},
};
use tracing::{debug, info, warn};
use x_wing::{
    DecapsulationKey,
    kem::{Decapsulator, KeyExport},
};

const TICKET_TTL: Duration = Duration::from_secs(600);
const ROTATE: u64 = 7 * 86400; // X-Wing key epoch (forward secrecy)
const PUSH_TTL: Duration = Duration::from_secs(86400);
// Learned per network up to RFC 5382's floor for NAT TCP idle timeouts
// (2 h 4 min).
const HB: (Duration, Duration) =
    (Duration::from_secs(120), Duration::from_secs(2 * 3600));
// Hosts: wired, not learned.
const HOST_HB: Duration = Duration::from_secs(28 * 60);
// Learned heartbeat: inbound limit found, stop probing.
const SETTLED: u32 = 1 << 31;
const MAX_PENDING: usize = 256; // per peer
const MAX_OUTBOX: usize = 256;
const MAX_DEVICE_RELAYS: usize = 4; // per device
const MAX_LISTEN: usize = 8;
const MAX_SEEN: usize = 1 << 16; // frame ids remembered against replay
// Control frames per device per minute (each Hello re-seals its queue).
const MAX_RATE: u32 = 16;
// A ping unanswered this long: the path is dead.
const PONG: Duration = Duration::from_secs(15);
/// `Node::network(OFFLINE)`: no network; the device parks instead of retrying.
pub const OFFLINE: u64 = u64::MAX;
/// The node this process runs for the whole phone (Android's owner), so
/// apps in it send and hear events through it too.
static SHARED: OnceLock<Arc<Node>> = OnceLock::new();
type Tap = Box<dyn Fn(EndpointId, &[u8]) + Send + Sync>;
static TAPS: Mutex<Vec<(App, Tap)>> = Mutex::new(vec![]);

pub fn shared() -> Option<Arc<Node>> {
    SHARED.get().cloned()
}

pub(crate) fn share(n: Arc<Node>) {
    let _ = SHARED.set(n);
}

/// What the shared node hears for `app`, in this process: to `f`, not the
/// platform.
pub fn tap(app: App, f: impl Fn(EndpointId, &[u8]) + Send + Sync + 'static) {
    let mut t = TAPS.lock().unwrap_or_else(|e| e.into_inner());
    t.retain(|x| x.0 != app);
    t.push((app, Box::new(f)));
}

pub(crate) fn tapped(from: EndpointId, app: &App, d: &[u8]) -> bool {
    let t = TAPS.lock().unwrap_or_else(|e| e.into_inner());
    let f = t.iter().find(|x| x.0 == *app);
    f.map(|f| (f.1)(from, d)).is_some()
}

/// Most an event carries: under a frame, so never taken for one.
pub const EVENT: usize = FRAME - 17;

type Tx = mpsc::UnboundedSender<(EndpointId, Vec<u8>)>;

/// Issued by this host.
struct Secret {
    s: [u8; 32],
    grant: Role,
    exp: Instant,
    used: Option<EndpointId>,
}
/// A ticket being redeemed.
struct Join {
    host: EndpointId,
    s: [u8; 32],
    exp: Instant,
    relays: Vec<Relay>,
}
impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.s)
    }
}
impl Drop for Join {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.s)
    }
}
/// A queued push, re-sealed per send.
struct Pend {
    to: EndpointId,
    app: App,
    data: Vec<u8>,
    exp: Instant,
    apns: bool,
}

/// Peer: opened with the pair's previous PSK when true.
enum Opened {
    Peer(Vec<u8>, bool),
    Issued(usize, Vec<u8>),
    Joined(Vec<u8>),
}

struct State {
    d: Disk,
    dk: [DecapsulationKey; 2], // current, previous
    secrets: Vec<Secret>,
    join: Option<Join>,
    // Joined another mesh on its relay: back to ours at the next pairing tick.
    home: bool,
    pending: HashMap<Id, Pend>,
    nack: HashMap<EndpointId, Instant>, // rate limit for key-resync Hellos
    // Control frame ids until they leave the freshness window, in expiry
    // order too.
    seen: HashSet<Id>,
    seen_q: VecDeque<(Instant, Id)>,
    // Device: control frames this minute.
    rate: HashMap<EndpointId, (Instant, u32)>,
    // Host: one outstanding echo per device.
    echo_until: HashMap<EndpointId, Instant>,
    via: HashMap<EndpointId, String>, // relay each peer was last heard on
    // Device: failing relays, skipped until then.
    down: HashMap<String, (Instant, Duration)>,
    net: u64,
    // Device: unix time a heartbeat probe ends (suspend stops monotonic
    // clocks).
    probe: u64,
    echoed: bool,
    echo_alive: bool,
    // Host: unix time until which it holds n0's relay (`want_n0`).
    n0_until: AtomicU64,
}

impl State {
    fn new(d: Disk) -> Self {
        let dk =
            [DecapsulationKey::from(d.xw), DecapsulationKey::from(d.xw_prev)];
        Self {
            d,
            dk,
            secrets: vec![],
            join: None,
            home: false,
            pending: HashMap::new(),
            nack: HashMap::new(),
            seen: HashSet::new(),
            seen_q: VecDeque::new(),
            rate: HashMap::new(),
            echo_until: HashMap::new(),
            via: HashMap::new(),
            down: HashMap::new(),
            net: 0,
            probe: 0,
            echoed: false,
            echo_alive: false,
            n0_until: AtomicU64::new(0),
        }
    }
    fn id(&self) -> EndpointId {
        self.d.sk.public()
    }
    fn hb(&self, net: u64) -> Duration {
        if self.d.role == Role::Host {
            return HOST_HB;
        }
        self.d
            .hb
            .get(&net)
            .map_or(HB.0, |s| Duration::from_secs((s & !SETTLED) as u64))
    }
    fn ek(&self) -> Vec<u8> {
        self.dk[0].encapsulation_key().to_bytes().to_vec()
    }
    fn hosts(&self) -> Vec<EndpointId> {
        self.d
            .peers
            .iter()
            .filter(|p| p.1.role == Role::Host)
            .map(|p| *p.0)
            .collect()
    }
    fn relays_msg(&self) -> Vec<u8> {
        [&self.d.relays_ver.to_le_bytes()[..], &Relay::enc(&self.d.relays)]
            .concat()
    }

    /// key epoch | ek | tag(mesh relays) | device: its app's relays (hosts
    /// listen there)
    fn hello(&self) -> Vec<u8> {
        let app = if self.d.role == Role::Device {
            Relay::enc(&self.uses())
        } else {
            lp(&[])
        };
        [
            &self.d.rotated.to_le_bytes()[..],
            &self.ek(),
            &tag(&self.relays_msg()),
            &app,
        ]
        .concat()
    }

    /// Device: the relays it may be on, announced so every mesh's hosts listen
    /// there.
    fn uses(&self) -> Vec<Relay> {
        relay::dedup(self.d.relays.iter().chain(&self.d.app).cloned())
    }

    /// Device: preference order. Unpaired: only where the ticket's host
    /// listens; joining another mesh: there first, until its host answers.
    fn candidates(&self) -> Vec<Relay> {
        let app =
            self.d.app.iter().filter(|_| !self.hosts().is_empty()).cloned();
        let join = self.join.iter().flat_map(|j| j.relays.iter().cloned());
        let all = relay::dedup(
            join.chain(self.d.relays.iter().cloned())
                .chain(app)
                .chain(relay::fallback(&self.d.relays)),
        ); // n0: the last resort
        let t = Instant::now();
        let up: Vec<_> = all
            .iter()
            .filter(|r| self.down.get(&r.url).is_none_or(|d| d.0 <= t))
            .cloned()
            .collect();
        if up.is_empty() { all } else { up }
    }

    /// Host: everywhere a member might be. Every device's first relay, then the
    /// others' round-robin up to MAX_LISTEN, in id order: no device crowds out
    /// another.
    fn listen(&self) -> Vec<Relay> {
        let mut devs: Vec<_> =
            self.d.peers.iter().filter(|p| p.1.role == Role::Device).collect();
        devs.sort_by_key(|p| p.0.as_bytes());
        let nth =
            |i| devs.iter().filter_map(move |p| p.1.relays.get(i).cloned());
        let mut l = relay::dedup(self.d.relays.iter().cloned().chain(nth(0)));
        for r in (1..MAX_DEVICE_RELAYS).flat_map(nth) {
            if l.len() < MAX_LISTEN && !l.iter().any(|x| x.url == r.url) {
                l.push(r)
            }
        }
        let n0 = relay::fallback(&self.d.relays).filter(|_| self.n0());
        relay::dedup(l.into_iter().chain(n0))
    }

    /// Host: whether to hold n0's relay too. Always when the mesh has no relay
    /// of its own (n0 is then its relay); else only while a device may be
    /// there, as a stock relay pings every 16-20 s.
    fn n0(&self) -> bool {
        let own = self.d.relays.iter().any(|r| r.url != relay::NO_N0);
        !own || self.n0_until.load(Relaxed) > now()
    }

    /// Host: hold n0's relay for an hour more, as device `id` may be there
    /// (we must reach it and do not know where, or heard it there). True when
    /// that starts it.
    fn want_n0(&self, id: EndpointId) -> bool {
        let dev = self.d.peers.get(&id).is_some_and(|p| p.role == Role::Device);
        let fallback = relay::fallback(&self.d.relays).is_some();
        if self.d.role != Role::Host || !dev || !fallback {
            return false;
        }
        self.n0_until.swap(now() + 3600, Relaxed) <= now()
    }

    fn frame(
        &self,
        to: EndpointId,
        kind: Kind,
        id: &Id,
        app: &App,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let p = self.d.peers.get(&to).context("unknown peer")?;
        Ok(proto::seal(
            &p.psk,
            Some(&p.ek),
            self.id(),
            to,
            &proto::plain(kind, id, app, data)?,
        ))
    }

    /// Our re-keying secret (`answer`: never answered back), sealed with `psk`
    /// (current or previous).
    fn key(
        &self,
        to: EndpointId,
        psk: &[u8; 32],
        c: &[u8; 32],
        answer: bool,
    ) -> Result<Vec<u8>> {
        let p = self.d.peers.get(&to).context("unknown peer")?;
        Ok(proto::seal(
            psk,
            Some(&p.ek),
            self.id(),
            to,
            &proto::plain(
                Kind::Key,
                &rnd(),
                &[0; 16],
                &[&c[..], &[answer as u8]].concat(),
            )?,
        ))
    }

    fn open(&self, from: EndpointId, f: &[u8]) -> Option<Opened> {
        let me = self.id();
        if let Some(p) = self.d.peers.get(&from) {
            // PSK mode: key resync only.
            let psk_hello = || {
                proto::open_psk(&p.psk, from, me, f)
                    .filter(|pt| pt[0] == Kind::Hello as u8)
            };
            if let Some(pt) = proto::open_kem(&self.dk, &p.psk, from, me, f)
                .or_else(psk_hello)
            {
                return Some(Opened::Peer(pt, false));
            }
            // Sent before they mixed.
            if let Mix::Done(prev, _) = &p.mix
                && let Some(pt) = proto::open_kem(&self.dk, prev, from, me, f)
            {
                return Some(Opened::Peer(pt, true));
            }
        }
        // Else (or not decryptable): a pairing retry from a just-paired peer
        // is still answered.
        let t = Instant::now();
        if let Some(j) =
            self.join.as_ref().filter(|j| j.host == from && j.exp > t)
        {
            return proto::open_psk(&j.s, from, me, f).map(Opened::Joined);
        }
        self.secrets
            .iter()
            .enumerate()
            .filter(|(_, s)| s.exp > t && s.used.is_none_or(|u| u == from))
            .find_map(|(i, s)| {
                proto::open_psk(&s.s, from, me, f)
                    .map(|pt| Opened::Issued(i, pt))
            })
    }
}

pub struct Node {
    st: Mutex<State>,
    path: PathBuf,
    kek: [u8; 32],
    sessions: Mutex<HashMap<String, Tx>>, // live relay connections
    // Frames made while no relay is connected.
    outbox: Mutex<VecDeque<(EndpointId, Vec<u8>)>>,
    // APNs fallback: (push id, wait for relay ack).
    atx: mpsc::UnboundedSender<(Id, bool)>,
    arx: Mutex<Option<mpsc::UnboundedReceiver<(Id, bool)>>>,
    kick: Notify,
    reset: Notify,
    changed: Notify,
    paused: AtomicBool,
    // Relay in use (device), for "using the n0 fallback" notices.
    relay: watch::Sender<Option<String>>,
}

/// iOS Notification Service Extension: decrypt an APNs payload's `f` field with
/// the app's state, read-only, on the phone. `None`: not ours, not a push, or
/// already delivered.
pub fn open_notification(
    path: &Path,
    kek: &[u8; 32],
    f_b64: &str,
) -> Result<Option<(EndpointId, App, Vec<u8>)>> {
    let (st, f) =
        (State::new(store::load(path, kek)?), BASE64.decode(f_b64.as_bytes())?);
    for from in st.d.peers.keys() {
        // the payload names no sender (Apple never learns it): try each peer
        let p = &st.d.peers[from];
        let prev = || {
            if let Mix::Done(prev, _) = &p.mix {
                proto::open_kem(&st.dk, prev, *from, st.id(), &f)
            } else {
                None
            }
        }; // as State::open
        if let Some(pt) =
            proto::open_kem(&st.dk, &p.psk, *from, st.id(), &f).or_else(prev)
        {
            let m = proto::parse(&pt)?;
            return Ok((m.kind == Kind::Push
                && store::first_delivery(path, &m.id, m.ts)?)
            .then(|| (*from, m.app, m.data.to_vec())));
        }
    }
    Ok(None)
}

impl Node {
    /// Found a new mesh; this node is its first host. `relays`: your own
    /// (preferred), may be empty.
    pub fn create(
        path: impl Into<PathBuf>,
        kek: [u8; 32],
        relays: Vec<Relay>,
    ) -> Result<Self> {
        let path = path.into();
        ensure!(
            !path.exists(),
            "{} exists: refusing to replace an identity",
            path.display()
        );
        let mut d = Disk::new(Role::Host, relays, vec![]);
        d.relays_ver = now();
        Self::boot(path, kek, d)
    }

    /// Join with a one-time ticket. Pairing completes (and is retried) once
    /// `run` reaches a relay. `app`: the app developer's default relays; used
    /// after the mesh's own.
    pub fn join(
        path: impl Into<PathBuf>,
        kek: [u8; 32],
        ticket: &str,
        app: Vec<Relay>,
    ) -> Result<Self> {
        let (j, role) = parse_ticket(ticket)?;
        let path = path.into();
        ensure!(
            !path.exists(),
            "{} exists: refusing to replace an identity",
            path.display()
        );
        let mut d = Disk::new(role, j.relays.clone(), app);
        d.home = *j.host.as_bytes();
        let n = Self::boot(path, kek, d)?;
        n.lock().join = Some(j);
        Ok(n)
    }

    /// Device: also join another mesh (another host's device ticket), so one
    /// device per phone serves apps whose hosts differ. Its hosts can revoke
    /// only their own mesh's peers, and only the first mesh sets our relays. A
    /// host of a mesh already joined: nothing to do.
    pub fn add(&self, ticket: &str) -> Result<()> {
        let (j, role) = parse_ticket(ticket)?;
        let mut st = self.lock();
        ensure!(
            st.d.role == Role::Device && role == Role::Device,
            "only devices join more meshes"
        );
        if st.d.peers.contains_key(&j.host) {
            return Ok(());
        }
        st.join = Some(j);
        drop(st);
        // Reconnect where the ticket's host listens.
        self.reset.notify_waiters();
        Ok(())
    }

    /// Whether `id` is our peer (e.g. a ticket's host, once joined).
    pub fn has(&self, id: &EndpointId) -> bool {
        self.lock().d.peers.contains_key(id)
    }

    /// Every later start. Devices pass their app's current default relays
    /// (updates may change them).
    pub fn open(
        path: impl Into<PathBuf>,
        kek: [u8; 32],
        app: Vec<Relay>,
    ) -> Result<Self> {
        let path = path.into();
        let mut d = store::load(&path, &kek)?;
        if d.role == Role::Device {
            d.app = app;
        }
        Self::boot(path, kek, d)
    }

    fn boot(path: PathBuf, kek: [u8; 32], d: Disk) -> Result<Self> {
        let (atx, arx) = mpsc::unbounded_channel();
        let n = Self {
            st: Mutex::new(State::new(d)),
            path,
            kek,
            sessions: Mutex::default(),
            outbox: Mutex::default(),
            atx,
            arx: Mutex::new(Some(arx)),
            kick: Notify::new(),
            reset: Notify::new(),
            changed: Notify::new(),
            paused: AtomicBool::new(false),
            relay: watch::channel(None).0,
        };
        n.save(&n.lock())?;
        Ok(n)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn save(&self, st: &State) -> Result<()> {
        store::save(&self.path, &self.kek, &st.d)
    }

    pub fn id(&self) -> EndpointId {
        self.lock().id()
    }
    pub fn role(&self) -> Role {
        self.lock().d.role
    }
    pub fn peers(&self) -> Vec<(EndpointId, Role)> {
        self.lock().d.peers.iter().map(|(i, p)| (*i, p.role)).collect()
    }
    pub fn relays(&self) -> Vec<Relay> {
        self.lock().d.relays.clone()
    }

    /// The relay this device is connected through (None: offline). Apps can
    /// show a notice while it is n0's public fallback (`relay::is_n0`): still
    /// end-to-end encrypted, n0 sees ids, IPs and timing.
    pub fn relay_watch(&self) -> watch::Receiver<Option<String>> {
        self.relay.subscribe()
    }

    /// Queue a push (<= BODY bytes) until acked, for up to 24 h. iOS peers:
    /// relay if connected, else straight to APNs.
    pub fn push(&self, to: EndpointId, app: &App, data: &[u8]) -> Result<()> {
        let (id, mut st) = (rnd(), self.lock());
        let f = st.frame(to, Kind::Push, &id, app, data)?;
        self.out(&st, to, f);
        if !st.d.apns.is_empty()
            && apns::parse_route(&st.d.peers[&to].route, app).is_ok()
        {
            let _ = self.atx.send((id, st.via.contains_key(&to)));
        }
        if st.pending.values().filter(|p| p.to == to).count() >= MAX_PENDING {
            // drop the oldest for this peer
            if let Some(old) = st
                .pending
                .iter()
                .filter(|p| p.1.to == to)
                .min_by_key(|p| p.1.exp)
                .map(|p| *p.0)
            {
                st.pending.remove(&old);
            }
        }
        st.pending.insert(
            id,
            Pend {
                to,
                app: *app,
                data: data.to_vec(),
                exp: Instant::now() + PUSH_TTL,
                apns: false,
            },
        );
        Ok(())
    }

    /// An event for app `app` on `to`, now, through `relay` if we are on
    /// it: one datagram, neither queued, acked nor sealed (the app seals and
    /// acks its own). Whether it left.
    pub fn event(
        &self,
        to: EndpointId,
        relay: &str,
        app: &App,
        d: &[u8],
    ) -> bool {
        let Ok(want) = relay.parse::<RelayUrl>() else { return false };
        let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let tx = s.iter().find(|(u, _)| u.parse().ok() == Some(want.clone()));
        let ok = d.len() <= EVENT;
        ok && tx.is_some_and(|t| t.1.send((to, [app, d].concat())).is_ok())
    }

    /// The relays we are on now: where events reach us.
    pub fn on(&self) -> Vec<String> {
        let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.keys().cloned().collect()
    }

    /// iOS device: register or refresh one app's APNs token (`topic` = its
    /// bundle id; several apps share the device). Announced to hosts, sealed.
    pub fn set_route(&self, svc: Svc, topic: &str, token: &[u8]) -> Result<()> {
        let e = apns::route(svc, topic, token)?;
        let mut st = self.lock();
        let r = apns::merge(&st.d.route, &e);
        if st.d.route == r {
            return Ok(());
        }
        st.d.route = r;
        self.save(&st)?;
        self.send_routes(&st)
    }

    fn send_routes(&self, st: &State) -> Result<()> {
        if !st.d.route.is_empty() {
            for h in st.hosts() {
                self.send(st, h, Kind::Route, &st.d.route)?;
            }
        }
        Ok(())
    }

    /// Host: your Apple team's APNs auth key (.p8); one key covers all your
    /// apps.
    pub fn set_apns_key(
        &self,
        key_id: &str,
        team_id: &str,
        p8_pem: &str,
    ) -> Result<()> {
        let creds = format!("{key_id} {team_id}\n{p8_pem}");
        apns::jwt(&creds)?; // validate now
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts send to APNs");
        st.d.apns = creds.into_bytes();
        self.save(&st)
    }

    /// One-time ticket, valid 10 minutes (QR code or in-band). Hosts only.
    /// Treat it as a secret.
    pub fn ticket(&self, grant: Role) -> Result<String> {
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts issue tickets");
        let (s, t) = (rnd(), Instant::now());
        st.secrets.retain(|x| x.exp > t);
        st.secrets.push(Secret { s, grant, exp: t + TICKET_TTL, used: None });
        Ok(format!(
            "irpush5:{}@{}",
            hex::encode([&st.id().as_bytes()[..], &s, &[grant as u8]].concat()),
            Relay::show(&st.d.relays)
        ))
    }

    /// Remove a member everywhere (flooded host to host; accepted only from
    /// hosts).
    pub fn revoke(&self, id: EndpointId) -> Result<()> {
        ensure!(self.role() == Role::Host, "only hosts revoke");
        self.apply_revoke(id)
    }

    /// Set the mesh's own relays (preference order). Sent sealed to every
    /// member; offline ones get it on their next Hello; devices switch on their
    /// next connect.
    pub fn set_relays(&self, l: Vec<Relay>) -> Result<()> {
        let mut st = self.lock();
        ensure!(st.d.role == Role::Host, "only hosts set the mesh relays");
        (st.d.relays, st.d.relays_ver) = (l, now().max(st.d.relays_ver + 1));
        self.save(&st)?;
        for p in st.d.peers.keys() {
            self.send(&st, *p, Kind::Relays, &st.relays_msg())?;
        }
        self.changed.notify_one();
        Ok(())
    }

    /// Android: ConnectivityManager.NetworkCallback; iOS: NWPathMonitor (any
    /// stable id per network). `OFFLINE` when there is no network: the device
    /// parks until the next call.
    pub fn network(&self, id: u64) {
        self.lock().net = id;
        self.reset.notify_waiters();
    }
    /// Android: from an AlarmManager alarm (in-process timers stall during
    /// suspend): heartbeat now. Returns when to call again: the end of a
    /// heartbeat probe, else the learned heartbeat.
    pub fn kick(&self) -> Duration {
        self.kick.notify_one();
        let (st, t) = (self.lock(), now());
        if st.probe > t {
            Duration::from_secs(st.probe - t)
        } else {
            st.hb(st.net)
        }
    }
    /// iOS: true when backgrounded, so hosts switch to APNs immediately.
    pub fn pause(&self, p: bool) {
        self.paused.store(p, Relaxed);
        self.reset.notify_waiters();
    }

    fn apply_revoke(&self, id: EndpointId) -> Result<()> {
        let mut st = self.lock();
        if st.d.revoked.contains(&id) || id == st.id() {
            return Ok(());
        }
        st.d.revoked.push(id);
        st.d.peers.remove(&id);
        st.pending.retain(|_, p| p.to != id);
        self.save(&st)?;
        if st.d.role == Role::Host {
            for p in st.d.peers.keys() {
                self.send(&st, *p, Kind::Revoke, id.as_bytes())?;
            }
        }
        self.changed.notify_one(); // its relays leave the listen set
        Ok(())
    }

    fn send(
        &self,
        st: &State,
        to: EndpointId,
        kind: Kind,
        data: &[u8],
    ) -> Result<()> {
        self.out(st, to, st.frame(to, kind, &rnd(), &[0; 16], data)?);
        Ok(())
    }

    /// Route a frame to the relay the peer was last heard on; unknown: every
    /// live relay; none: outbox.
    fn out(&self, st: &State, to: EndpointId, f: Vec<u8>) {
        let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match st.via.get(&to).and_then(|u| s.get(u)) {
            Some(tx) => {
                let _ = tx.send((to, f));
            }
            None if s.is_empty() => {
                self.want_n0(st, to);
                let mut o =
                    self.outbox.lock().unwrap_or_else(|e| e.into_inner());
                if o.len() >= MAX_OUTBOX {
                    o.pop_front();
                }
                o.push_back((to, f));
            }
            None => {
                self.want_n0(st, to);
                for tx in s.values() {
                    let _ = tx.send((to, f.clone()));
                }
            }
        }
    }

    fn want_n0(&self, st: &State, id: EndpointId) {
        if st.want_n0(id) {
            self.changed.notify_one();
        }
    }

    fn handle(
        &self,
        url: &str,
        from: EndpointId,
        f: &[u8],
        on: &impl Fn(EndpointId, App, &[u8]),
    ) -> Result<()> {
        // Not a frame's size: an event, the app's to check.
        if f.len() != FRAME {
            if let Some((app, d)) = f.split_first_chunk::<16>() {
                on(from, *app, d);
            }
            return Ok(());
        }
        let mut st = self.lock();
        let Some(opened) = st.open(from, f) else {
            // A known peer we cannot decrypt holds a stale key of ours: resync
            // (PSK mode), rate-limited.
            let t = Instant::now();
            if let Some(p) =
                st.d.peers
                    .get(&from)
                    .filter(|_| st.nack.get(&from).is_none_or(|x| t > *x))
            {
                let f = proto::seal(
                    &p.psk,
                    None,
                    st.id(),
                    from,
                    &proto::plain(Kind::Hello, &rnd(), &[0; 16], &st.hello())?,
                );
                let key = match p.mix {
                    Mix::Sent(c) => Some(st.key(from, &p.psk, &c, false)?),
                    _ => None,
                }; // or they mixed and our Key was lost
                st.nack.insert(from, t + Duration::from_secs(60));
                self.out(&st, from, f);
                if let Some(k) = key {
                    self.out(&st, from, k);
                }
            }
            return Ok(());
        };
        st.via.insert(from, url.to_string());
        if relay::is_n0(url) {
            self.want_n0(&st, from); // still there: stay
        }
        match opened {
            Opened::Issued(i, pt) => {
                self.on_pair_request(&mut st, i, from, &pt)
            }
            Opened::Joined(pt) => self.on_pair_reply(&mut st, from, &pt),
            Opened::Peer(pt, prev) => {
                let m = proto::parse(&pt)?;
                let host =
                    st.d.peers.get(&from).is_some_and(|p| p.role == Role::Host);
                if !prev
                    && let Some(p) = st.d.peers.get_mut(&from)
                    && let Mix::Done(..) = p.mix
                {
                    p.mix = Mix::Fixed;
                    self.save(&st)?;
                } // they use the mixed PSK
                // Replay: pushes are de-duplicated by the delivered-id log,
                // Acks are idempotent; every other kind here (a relay may
                // resend any frame inside the freshness window). Devices
                // are rate-limited; when full, a device's frame is dropped, a
                // host's evicts the oldest.
                if !matches!(m.kind, Kind::Push | Kind::Ack) {
                    let t = Instant::now();
                    if !host {
                        let w = st.rate.entry(from).or_insert((t, 0));
                        if t >= w.0 + Duration::from_secs(60) {
                            *w = (t, 0)
                        }
                        w.1 += 1;
                        if w.1 > MAX_RATE {
                            return Ok(());
                        }
                    }
                    while let Some(&(x, id)) = st.seen_q.front()
                        && x <= t
                    {
                        st.seen_q.pop_front();
                        st.seen.remove(&id);
                    }
                    if st.seen.len() >= MAX_SEEN {
                        if !host {
                            return Ok(());
                        }
                        if let Some((_, o)) = st.seen_q.pop_front() {
                            st.seen.remove(&o);
                        }
                    }
                    if !st.seen.insert(m.id) {
                        return Ok(());
                    }
                    st.seen_q.push_back((
                        t + Duration::from_secs(
                            proto::MAX_AGE + proto::MAX_SKEW,
                        ),
                        m.id,
                    ));
                }
                let mut r = Rd(m.data);
                match m.kind {
                    Kind::Push => {
                        self.out(
                            &st,
                            from,
                            st.frame(from, Kind::Ack, &rnd(), &m.id, &[])?,
                        ); // app field carries the acked id
                        drop(st);
                        if store::first_delivery(&self.path, &m.id, m.ts)? {
                            on(from, m.app, m.data);
                        } // else retransmit / iOS extension had it
                    }
                    Kind::Ack => {
                        st.pending.remove(&m.app);
                    }
                    Kind::Hello => self.on_hello(&mut st, from, &mut r)?,
                    Kind::Intro if host => {
                        let (id, role, ek, psk) =
                            (r.id()?, Role::of(r.u8()?), r.ek()?, r.arr()?);
                        // Devices never take devices.
                        let met = role == Role::Host || st.d.role == Role::Host;
                        if met
                            && id != st.id()
                            && !st.d.revoked.contains(&id)
                            && !st.d.peers.contains_key(&id)
                        {
                            let mesh =
                                st.d.peers
                                    .get(&from)
                                    .map_or([0; 32], |p| p.mesh);
                            st.d.peers.insert(
                                id,
                                Peer {
                                    ek,
                                    psk,
                                    role,
                                    ts: 0,
                                    route: vec![],
                                    relays: vec![],
                                    mix: Mix::None,
                                    mesh,
                                },
                            );
                            self.save(&st)?;
                            self.send(&st, id, Kind::Hello, &st.hello())?;
                        }
                    }
                    Kind::Revoke if host => {
                        let id = r.id()?;
                        // A device takes a revoke only for a peer of the
                        // revoking host's own mesh.
                        let mesh = |i| st.d.peers.get(i).map(|p: &Peer| p.mesh);
                        if st.d.role == Role::Device
                            && (mesh(&id).is_none() || mesh(&id) != mesh(&from))
                        {
                            return Ok(());
                        }
                        drop(st);
                        self.apply_revoke(id)?;
                    }
                    Kind::Relays
                        if host
                            && (st.d.role == Role::Host
                                || st
                                    .d
                                    .peers
                                    .get(&from)
                                    .is_some_and(|p| p.mesh == st.d.home)) =>
                    {
                        let (ver, l) = (r.u64()?, Relay::dec(&mut r)?);
                        if ver > st.d.relays_ver {
                            (st.d.relays, st.d.relays_ver) = (l, ver);
                            self.save(&st)?;
                            self.changed.notify_one();
                        }
                    }
                    Kind::Echo
                        if st.d.role == Role::Host && m.data.len() == 4 =>
                    {
                        self.on_echo_request(&mut st, from, &mut r)?
                    }
                    Kind::Echo if host => {
                        if m.data.is_empty() {
                            st.echoed = true
                        } else {
                            st.echo_alive = true
                        }
                    }
                    Kind::Key => self.on_key(&mut st, from, prev, &mut r)?,
                    Kind::Route
                        if st.d.role == Role::Host
                            && !host
                            && apns::valid(m.data) =>
                    {
                        let changed =
                            st.d.peers
                                .get_mut(&from)
                                .filter(|p| p.route != m.data)
                                .map(|p| p.route = m.data.to_vec())
                                .is_some();
                        if changed {
                            self.save(&st)?;
                        }
                    }
                    k => debug!(?k, %from, "ignored"),
                }
                Ok(())
            }
        }
    }

    /// Host: a ticket holder pairs. Idempotent per secret, so the joiner can
    /// retry until it hears back.
    fn on_pair_request(
        &self,
        st: &mut State,
        i: usize,
        from: EndpointId,
        pt: &[u8],
    ) -> Result<()> {
        let m = proto::parse(pt)?;
        ensure!(m.kind == Kind::Pair, "expected pair");
        let (s, grant, first) = (
            st.secrets[i].s,
            st.secrets[i].grant,
            st.secrets[i].used.is_none(),
        );
        if first {
            let mut r = Rd(m.data);
            let ek = r.ek()?;
            let relays = if grant == Role::Device {
                device_relays(Relay::dec(&mut r).unwrap_or_default())
            } else {
                vec![]
            };
            st.secrets[i].used = Some(from);
            st.d.peers.insert(
                from,
                Peer {
                    ek,
                    psk: proto::pair_psk(&s, st.id(), from),
                    role: grant,
                    ts: 0,
                    route: vec![],
                    relays,
                    mix: Mix::None,
                    mesh: [0; 32],
                },
            );
            self.save(st)?;
            self.changed.notify_one();
            info!(%from, ?grant, "paired");
        }
        // Reply first (the joiner must know us before our introductions
        // arrive). Retries repeat both; introductions are idempotent
        // (deterministic PSK), so a lost frame never splits a pair.
        let reply = proto::plain(
            Kind::Pair,
            &rnd(),
            &[0; 16],
            &[&[st.d.role as u8][..], &st.ek()].concat(),
        )?;
        self.out(st, from, proto::seal(&s, None, st.id(), from, &reply));
        // Devices meet hosts only: a host may serve many people's phones
        // without telling one of another.
        let others: Vec<_> = st
            .d
            .peers
            .iter()
            .filter(|p| {
                *p.0 != from && (grant == Role::Host || p.1.role == Role::Host)
            })
            .map(|p| *p.0)
            .collect();
        for o in others {
            self.introduce(st, from, o)?;
        }
        Ok(())
    }

    /// Joiner: (re)send the pairing request, sealed with the ticket secret.
    fn pair_request(&self, st: &State) -> Result<()> {
        let Some(j) = st.join.as_ref().filter(|j| j.exp > Instant::now())
        else {
            return Ok(());
        };
        let pt = proto::plain(
            Kind::Pair,
            &rnd(),
            &[0; 16],
            &[st.ek(), Relay::enc(&st.uses())].concat(),
        )?;
        self.out(st, j.host, proto::seal(&j.s, None, st.id(), j.host, &pt));
        Ok(())
    }

    /// Joiner: the ticket's host answered.
    fn on_pair_reply(
        &self,
        st: &mut State,
        from: EndpointId,
        pt: &[u8],
    ) -> Result<()> {
        let m = proto::parse(pt)?;
        ensure!(m.kind == Kind::Pair, "expected pair");
        // Another mesh: back to our own relays after.
        let more = !st.hosts().is_empty();
        let s = st.join.take().context("no join")?.s;
        let mut r = Rd(m.data);
        let (role, ek) = (Role::of(r.u8()?), r.ek()?);
        st.d.peers.insert(
            from,
            Peer {
                ek,
                psk: proto::pair_psk(&s, st.id(), from),
                role,
                ts: 0,
                route: vec![],
                relays: vec![],
                mix: Mix::None,
                mesh: *from.as_bytes(),
            },
        );
        self.save(st)?;
        if role == Role::Host {
            self.send(st, from, Kind::Hello, &st.hello())?;
        }
        st.home = more;
        info!(%from, "joined");
        Ok(())
    }

    /// A peer is online, maybe with a rotated key, new APNs token or new app
    /// relays.
    fn on_hello(
        &self,
        st: &mut State,
        from: EndpointId,
        r: &mut Rd,
    ) -> Result<()> {
        let (ts, ek, tg) = (r.u64()?, r.ek()?, r.arr::<8>()?);
        let relays = Relay::dec(r).unwrap_or_default();
        let me_host = st.d.role == Role::Host;
        let p = st.d.peers.get_mut(&from).context("peer")?;
        let rekey = ts >= p.ts && ek != p.ek;
        let relays = if me_host && p.role == Role::Device {
            device_relays(relays)
        } else {
            p.relays.clone()
        };
        let relays_changed = relays != p.relays;
        if rekey {
            (p.ek, p.ts) = (ek, ts);
        }
        p.relays = relays;
        let (start, key) = match p.mix {
            Mix::None => {
                let c = rnd();
                p.mix = Mix::Sent(c);
                (true, Some((p.psk, c)))
            }
            Mix::Sent(c) => (false, Some((p.psk, c))),
            Mix::Done(..) | Mix::Fixed => (false, None),
        };
        if rekey || relays_changed || start {
            self.save(st)?;
        }
        if let Some((psk, c)) = key {
            self.out(st, from, st.key(from, &psk, &c, false)?);
        } // re-key the pair between us (until done)
        if relays_changed {
            self.changed.notify_one();
        }
        if rekey {
            self.send(st, from, Kind::Hello, &st.hello())?;
        } // answer with ours once
        if me_host && tg != tag(&st.relays_msg()) {
            self.send(st, from, Kind::Relays, &st.relays_msg())?;
        } // missed an update
        self.flush(st, Some(from));
        Ok(())
    }

    /// The pair re-keys between themselves: each side's secret travels
    /// KEM-sealed to the other, so whoever knew the PSK before (the introducing
    /// host, a ticket's holder) cannot forge frames. Old peers ignore Key:
    /// their pairs keep the PSK they have.
    fn on_key(
        &self,
        st: &mut State,
        from: EndpointId,
        prev: bool,
        r: &mut Rd,
    ) -> Result<()> {
        let (theirs, answer, me) = (r.arr::<32>()?, r.u8()? == 1, st.id());
        let p = st.d.peers.get(&from).context("peer")?;
        let sent = matches!(p.mix, Mix::Sent(_));
        let (psk, c, mix) = match p.mix {
            Mix::Done(old, c) => {
                if prev && !answer {
                    self.out(st, from, st.key(from, &old, &c, true)?)
                }
                return Ok(());
            } // our answer was lost
            Mix::Fixed => return Ok(()),
            Mix::None if answer => return Ok(()), // answers only what we sent
            Mix::None => {
                let c = rnd();
                self.out(st, from, st.key(from, &p.psk, &c, true)?);
                (p.psk, c, Mix::Done(p.psk, c))
            }
            Mix::Sent(c) => (
                p.psk,
                c,
                if answer { Mix::Fixed } else { Mix::Done(p.psk, c) },
            ), // crossed: theirs may be in flight
        };
        let p = st.d.peers.get_mut(&from).context("peer")?;
        (p.psk, p.mix) = (proto::mix_psk(&psk, (me, &c), (from, &theirs)), mix);
        if sent {
            self.out(st, from, st.key(from, &st.d.peers[&from].psk, &c, true)?);
        } // confirm: they drop the old PSK
        self.save(st)
    }

    /// Host: "reach me after N s of silence" (tests the device's inbound path).
    /// One per device at a time.
    fn on_echo_request(
        &self,
        st: &mut State,
        from: EndpointId,
        r: &mut Rd,
    ) -> Result<()> {
        let d = Duration::from_secs((r.u32()? as u64).min(HB.1.as_secs()));
        let t = Instant::now();
        if st.echo_until.get(&from).is_some_and(|u| *u > t) {
            return Ok(());
        }
        st.echo_until.insert(from, t + d + Duration::from_secs(60));
        // "Alive": a missing echo then means the path, not us.
        self.send(st, from, Kind::Echo, &[0])?;
        let f = st.frame(from, Kind::Echo, &rnd(), &[0; 16], &[])?;
        let tx = st.via.get(&from).and_then(|u| {
            self.sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(u)
                .cloned()
        });
        if let Some(tx) = tx {
            tokio::spawn(async move {
                sleep(d).await;
                let _ = tx.send((from, f));
            });
        }
        Ok(())
    }

    /// Host: pairwise PSK for a and b, derived from our introduction secret so
    /// re-sending is idempotent. Only a start: the pair then mixes in secrets
    /// of its own (`on_key`).
    fn introduce(
        &self,
        st: &State,
        a: EndpointId,
        b: EndpointId,
    ) -> Result<()> {
        let psk = proto::intro_psk(&st.d.intro, a, b);
        let card = |x: EndpointId| -> Result<Vec<u8>> {
            let p = st.d.peers.get(&x).context("peer")?;
            Ok([&x.as_bytes()[..], &[p.role as u8], &p.ek.to_bytes(), &psk]
                .concat())
        };
        self.send(st, b, Kind::Intro, &card(a)?)?;
        self.send(st, a, Kind::Intro, &card(b)?)
    }

    fn flush(&self, st: &mut State, only: Option<EndpointId>) {
        let t = Instant::now();
        st.pending.retain(|_, p| p.exp > t);
        for (id, p) in
            st.pending.iter().filter(|p| only.is_none_or(|o| o == p.1.to))
        {
            if let Ok(f) = st.frame(p.to, Kind::Push, id, &p.app, &p.data) {
                self.out(st, p.to, f);
            }
        }
    }

    /// Weekly X-Wing key rotation, announced via Hello. Frames sealed to the
    /// previous key still open.
    fn rotate(&self, st: &mut State) -> Result<()> {
        if now() < st.d.rotated + ROTATE {
            return Ok(());
        }
        (st.d.xw_prev, st.d.xw, st.d.rotated) = (st.d.xw, rnd(), now());
        st.dk = [
            DecapsulationKey::from(st.d.xw),
            DecapsulationKey::from(st.d.xw_prev),
        ];
        self.save(st)?;
        for p in st.d.peers.keys() {
            self.send(st, *p, Kind::Hello, &st.hello())?;
        }
        Ok(())
    }

    /// Run forever; `on(sender, app, data)` fires once per push (wrap it with
    /// [`Local::deliver`] when serving other apps on this machine). Device: one
    /// relay connection. Host: one listener per candidate relay, plus the APNs
    /// sender.
    pub async fn run(&self, on: impl Fn(EndpointId, App, &[u8])) -> Result<()> {
        let arx = self
            .arx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .context("run called twice")?;
        // Shared: TLS resumption and the DNS cache.
        let tlsc = tls::CaTlsConfig::default().client_config(pq())?;
        let dns = DnsResolver::new();
        let relays = async {
            if self.role() == Role::Device {
                return self.relay_loop(None, &tlsc, &dns, &on).await;
            }
            let (mut loops, mut running) =
                (FuturesUnordered::new(), HashSet::new());
            loop {
                let want = self.lock().listen();
                for r in want {
                    if running.insert(r.url.clone()) {
                        loops.push(self.relay_loop(
                            Some(r.url),
                            &tlsc,
                            &dns,
                            &on,
                        ))
                    }
                }
                tokio::select! {
                    Some(u) = loops.next() => { running.remove(&u); }
                    _ = self.changed.notified() => {}
                }
            }
        };
        tokio::join!(relays, self.apns_loop(arx, tlsc.clone()));
        Ok(())
    }

    /// `fixed`: host listener for one relay (returns when it leaves the set).
    /// None: device, walks the candidates in preference order on every
    /// reconnect; a failing relay is skipped with backoff.
    async fn relay_loop(
        &self,
        fixed: Option<String>,
        tlsc: &rustls::ClientConfig,
        dns: &DnsResolver,
        on: &impl Fn(EndpointId, App, &[u8]),
    ) -> String {
        let mut backoff = Duration::from_millis(250);
        let idle = || {
            self.paused.load(Relaxed)
                || (fixed.is_none() && self.lock().net == OFFLINE)
        };
        loop {
            loop {
                // Paused or offline: no radio use until the platform says
                // otherwise. Registered before the check: no missed wakeup.
                let w = self.reset.notified();
                tokio::pin!(w);
                w.as_mut().enable();
                if !idle() {
                    break;
                }
                w.await;
            }
            let (cands, sk) = {
                let st = self.lock();
                let c = match &fixed {
                    Some(u) => st
                        .listen()
                        .into_iter()
                        .filter(|r| &r.url == u)
                        .collect(),
                    None => st.candidates(),
                };
                (c, st.d.sk.clone())
            };
            if cands.is_empty() {
                return fixed.unwrap_or_default();
            }
            for r in cands {
                let Ok(url) = r.url.parse::<RelayUrl>() else { continue };
                let b = ClientBuilder::new(url, sk.clone(), dns.clone())
                    .tls_client_config(tlsc.clone());
                match timeout(Duration::from_secs(8), b.connect()).await {
                    Ok(Ok(c)) => {
                        self.lock().down.remove(&r.url);
                        backoff = Duration::from_millis(250);
                        if let Err(e) = self.session(c, &r.url, on).await {
                            info!(relay = %r.url, "session ended: {e:#}")
                        }
                        break;
                    }
                    e => {
                        let why: String = e.map_or("timeout".into(), |e| {
                            e.err().map(|e| e.to_string()).unwrap_or_default()
                        });
                        warn!(relay = %r.url, "connect failed: {why}");
                        if fixed.is_none() {
                            let mut st = self.lock();
                            let d = st.down.get(&r.url).map_or(
                                Duration::from_secs(300),
                                |d| {
                                    (d.1 * 2).min(Duration::from_secs(6 * 3600))
                                },
                            );
                            st.down
                                .insert(r.url.clone(), (Instant::now() + d, d));
                        }
                    }
                }
            }
            if idle() {
                continue;
            }
            tokio::select! {
                _ = sleep(backoff) => {}
                _ = self.kick.notified() => {}
                _ = self.reset.notified() => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
    }

    async fn session(
        &self,
        mut c: Client,
        url: &str,
        on: &impl Fn(EndpointId, App, &[u8]),
    ) -> Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        for m in self.outbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..)
        {
            let _ = tx.send(m);
        }
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(url.to_string(), tx);
        if self.role() == Role::Device {
            if relay::is_n0(url) {
                warn!(
                    "using n0's public relay as fallback (end-to-end \
                     encrypted; n0 sees ids, IPs, timing)"
                )
            }
            self.relay.send_replace(Some(url.to_string()));
        }
        let r = self.session_inner(&mut c, url, &mut rx, on).await;
        if self.role() == Role::Device {
            self.relay.send_replace(None);
        }
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(url);
        self.lock().via.retain(|_, u| u != url);
        r
    }

    async fn session_inner(
        &self,
        c: &mut Client,
        url: &str,
        rx: &mut mpsc::UnboundedReceiver<(EndpointId, Vec<u8>)>,
        on: &impl Fn(EndpointId, App, &[u8]),
    ) -> Result<()> {
        // Registered once, before anything else: `notify_waiters` stores no
        // permit, so a fresh future per loop pass would miss a network change
        // or pause arriving mid-frame.
        let reset = self.reset.notified();
        tokio::pin!(reset);
        reset.as_mut().enable();
        if self.paused.load(Relaxed)
            || (self.role() == Role::Device && self.lock().net == OFFLINE)
        {
            bail!("paused or offline") // changed while connecting
        }
        let net = {
            let mut st = self.lock();
            self.rotate(&mut st)?;
            self.pair_request(&st)?;
            // "I'm back": hosts flush their queues.
            for h in st.hosts() {
                self.send(&st, h, Kind::Hello, &st.hello())?;
            }
            if st.d.role == Role::Device {
                self.send_routes(&st)?;
            }
            self.flush(&mut st, None);
            st.net
        };
        // Heartbeat learning tests the INBOUND path: a host echoes after the
        // candidate idle time. Outbound pings alone pass behind NATs/VPNs (e.g.
        // WireGuard without PersistentKeepalive) whose mapping still accepts
        // our ping but already drops unsolicited inbound pushes.
        let hb = |st: &State| st.hb(net);
        let settled =
            |st: &State| st.d.hb.get(&net).is_some_and(|s| s & SETTLED != 0);
        let learn = |st: &mut State, h: Duration, done: bool| -> Result<()> {
            let v = h.as_secs() as u32 | if done { SETTLED } else { 0 };
            if st.d.hb.insert(net, v) != Some(v) {
                self.save(st)?;
            }
            Ok(())
        };
        let probe_start =
            |st: &mut State| -> Result<Option<(Instant, Duration)>> {
                let (h, host) = (hb(st), st.hosts().first().copied());
                st.probe = 0;
                let Some(host) = host.filter(|_| {
                    st.d.role == Role::Device && !settled(st) && h < HB.1
                }) else {
                    return Ok(None);
                };
                let (c, slack) = ((h * 2).min(HB.1), Duration::from_secs(20));
                (st.echoed, st.echo_alive, st.probe) =
                    (false, false, now() + (c + slack).as_secs());
                self.send(
                    st,
                    host,
                    Kind::Echo,
                    &(c.as_secs() as u32).to_le_bytes(),
                )?;
                Ok(Some((Instant::now() + c + slack, c)))
            };
        let mut probe = probe_start(&mut self.lock())?;
        // Pairing retries, only while joining.
        let mut retry = Instant::now() + Duration::from_secs(5);
        let mut ping = None;
        let mut due = probe.map_or(Instant::now() + hb(&self.lock()), |p| p.0);
        let joining = || {
            let st = self.lock();
            st.join.is_some() || st.home
        };
        // Device: a better relay is up; host: this one is no longer needed.
        let moved = |st: &State| match st.d.role {
            Role::Device => {
                st.candidates().first().is_some_and(|r| r.url != url)
            }
            Role::Host => !st.listen().iter().any(|r| r.url == url),
        };
        loop {
            tokio::select! {
                m = c.next() => match m.context("closed")?? {
                    In::Datagrams { remote_endpoint_id: from, datagrams } => {
                        let f = &datagrams.contents;
                        if let Err(e) = self.handle(url, from, f, on) {
                            debug!(%from, "dropped frame: {e:#}")
                        }
                        let mut st = self.lock();
                        // Inbound survived c of silence: adopt, try double.
                        if let Some((_, c)) = probe.filter(|_| st.echoed) {
                            learn(&mut st, c, c >= HB.1)?;
                            probe = probe_start(&mut st)?;
                        }
                        // Traffic proves liveness.
                        if ping.is_none() {
                            let t = Instant::now() + hb(&st);
                            due = probe.map_or(t, |p| p.0);
                        }
                    }
                    // It left this relay; if we owe it pushes, maybe for n0.
                    In::EndpointGone(id) => {
                        let mut st = self.lock();
                        st.via.retain(|p, u| !(*p == id && u == url));
                        if st.pending.values().any(|p| p.to == id) {
                            self.want_n0(&st, id);
                        }
                    }
                    // A relay that pings us (a stock one: every 16-20 s of
                    // our silence) proves the inbound path as a push does,
                    // so its ping is our heartbeat; it also keeps the NAT
                    // awake, so no heartbeat is learned there. The radio is
                    // up anyway: a good moment to go back to a better relay.
                    In::Ping(d) => {
                        c.send(Out::Pong(d)).await?;
                        let mut st = self.lock();
                        if probe.take().is_some() {
                            st.probe = 0;
                        }
                        if ping.is_none() {
                            due = Instant::now() + hb(&st);
                        }
                        if moved(&st) {
                            bail!("moving: a better relay, or none needed");
                        }
                    }
                    In::Pong(d) if Some(d) == ping => {
                        (ping, due) = (None, Instant::now() + hb(&self.lock()))
                    }
                    _ => {}
                },
                Some((to, f)) = rx.recv() => {
                    let datagrams = f.into();
                    c.send(Out::Datagrams { dst_endpoint_id: to, datagrams })
                        .await?
                }
                _ = sleep_until(due) => {
                    // No lock may live across an await (keeps run() Send).
                    {
                        let mut st = self.lock();
                        if probe.take().is_some() {
                            st.probe = 0;
                            // Host alive, echo lost: inbound dies before 2x.
                            // Keep the current one, stop probing.
                            if st.echo_alive {
                                let h = hb(&st);
                                learn(&mut st, h, true)?;
                                bail!("inbound idle limit found");
                            }
                            // Host never answered: inconclusive, retry next
                            // session.
                            due = Instant::now();
                            continue;
                        }
                        // Mapping died: shorten this network's heartbeat,
                        // reconnect now.
                        if ping.is_some() {
                            let h = (hb(&st) / 2).max(HB.0);
                            learn(&mut st, h, true)?;
                            bail!("pong timeout");
                        }
                        // The radio is awake anyway: no extra wakeup.
                        if moved(&st) {
                            bail!("moving: a better relay, or none needed");
                        }
                        self.rotate(&mut st)?;
                    }
                    let d = rnd();
                    c.send(Out::Ping(d)).await?;
                    (ping, due) = (Some(d), Instant::now() + PONG);
                }
                _ = sleep_until(retry), if joining() => {
                    let (st, t) = (self.lock(), Instant::now());
                    // Another mesh joined: its introductions are in.
                    if st.join.is_none() {
                        drop(st);
                        self.lock().home = false;
                        bail!("back to our own relays")
                    }
                    if st.join.as_ref().is_some_and(|j| j.exp <= t) {
                        drop(st);
                        self.lock().join = None;
                        bail!("ticket expired before the host answered")
                    }
                    self.pair_request(&st)?;
                    retry = t + Duration::from_secs(5);
                }
                // An alarm: heartbeat now, or end a probe the phone slept
                // through (wall clock).
                _ = self.kick.notified() => {
                    if probe.is_none() || now() >= self.lock().probe {
                        due = Instant::now()
                    }
                }
                _ = &mut reset => bail!("reconnect (network change or pause)"),
            }
        }
    }

    /// Hosts post to APNs directly. `wait`: the peer looked connected; give the
    /// relay 1 s to deliver. Throttled or failing (429, 5xx, network): retried
    /// with backoff while the push is unacked.
    async fn apns_loop(
        &self,
        mut arx: mpsc::UnboundedReceiver<(Id, bool)>,
        mut tlsc: rustls::ClientConfig,
    ) {
        tlsc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let http = match reqwest::Client::builder()
            .tls_backend_preconfigured(tlsc)
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(h) => h,
            Err(e) => return warn!("apns client: {e}"),
        };
        let token = Mutex::new((String::new(), 0u64)); // JWT, reused 40 min
        let one = |id: Id, wait: bool| {
            let (http, token, t0) = (&http, &token, Instant::now());
            async move {
                for d in [wait as u64, 10, 60, 300, 1800] {
                    sleep(Duration::from_secs(d)).await;
                    let (to, app, route, f, auth) = {
                        let st = self.lock();
                        let Some(p) = st.pending.get(&id).filter(|p| !p.apns)
                        else {
                            return Ok(());
                        }; // acked meanwhile
                        let (to, app, data) = (p.to, p.app, p.data.clone());
                        let route = apns::parse_route(
                            &st.d.peers.get(&to).context("peer")?.route,
                            &app,
                        )?;
                        let f = BASE64.encode(&st.frame(
                            to,
                            Kind::Push,
                            &id,
                            &app,
                            &data,
                        )?);
                        let mut t =
                            token.lock().unwrap_or_else(|e| e.into_inner());
                        if now() > t.1 + 2400 {
                            *t = (
                                apns::jwt(std::str::from_utf8(&st.d.apns)?)?,
                                now(),
                            );
                        }
                        (to, app, route, f, t.0.clone())
                    };
                    // A ring this late is no ring.
                    if route.voip() && t0.elapsed() > Duration::from_secs(20) {
                        return Ok(());
                    }
                    match apns::post(http, &route, &auth, &f).await? {
                        apns::Sent::Ok => {
                            if let Some(p) = self.lock().pending.get_mut(&id) {
                                p.apns = true;
                            }
                            return Ok(());
                        }
                        apns::Sent::Gone => {
                            // token dead: stop using it
                            let mut st = self.lock();
                            if let Some(p) = st.d.peers.get_mut(&to) {
                                p.route = apns::remove(&p.route, &app);
                            }
                            return self.save(&st);
                        }
                        apns::Sent::Retry(e) => info!("apns, will retry: {e}"),
                    }
                }
                anyhow::bail!("gave up")
            }
        };
        let mut inflight = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some((id, wait)) = arx.recv() => inflight.push(one(id, wait)),
                Some(r) = inflight.next() => {
                    if let Err(e) = r { warn!("apns: {e:#}") }
                }
                else => return,
            }
        }
    }
}

/// aws-lc-rs, X25519MLKEM768 first. Never iroh-relay's `default_provider`: it
/// is ring (classical) whenever the embedding app's iroh enables `tls-ring`, as
/// iroh's defaults do.
fn pq() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::aws_lc_rs::default_provider().into()
}

/// Relays a device may make hosts dial: public https names only, a few per
/// device.
fn parse_ticket(t: &str) -> Result<(Join, Role)> {
    let (h, relays) = t
        .trim()
        .strip_prefix("irpush5:")
        .and_then(|t| t.split_once('@'))
        .context("bad ticket")?;
    let b = hex::decode(h)?;
    let mut r = Rd(&b);
    let (host, s, role) = (r.id()?, r.arr()?, Role::of(r.u8()?));
    ensure!(r.0.is_empty(), "bad ticket");
    Ok((
        Join {
            host,
            s,
            exp: Instant::now() + TICKET_TTL,
            relays: Relay::list(relays)?,
        },
        role,
    ))
}

fn device_relays(l: Vec<Relay>) -> Vec<Relay> {
    l.into_iter()
        .filter(|r| r.public().is_ok())
        .take(MAX_DEVICE_RELAYS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_hop_is_post_quantum_in_any_embedding() {
        assert_eq!(
            pq().kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
        );
    }

    #[test]
    fn n0_is_the_last_resort() {
        let mesh = || Relay::list("https://mesh.example/").unwrap();
        let urls =
            |l: Vec<Relay>| l.into_iter().map(|r| r.url).collect::<Vec<_>>();
        let st = State::new(Disk::new(Role::Device, mesh(), vec![]));
        assert_eq!(urls(st.candidates()), ["https://mesh.example/", N0]);
        // Hosts hold n0 only while a device may be there...
        let mut d = Disk::new(Role::Host, mesh(), vec![]);
        let dev = iroh_base::SecretKey::from_bytes(&rnd()).public();
        let ek =
            DecapsulationKey::from(rnd::<32>()).encapsulation_key().clone();
        d.peers.insert(dev, peer(Role::Device, ek, rnd(), ""));
        let st = State::new(d);
        assert_eq!(urls(st.listen()), ["https://mesh.example/"], "idle: no n0");
        assert!(!st.want_n0(st.id()), "hosts are not looked for there");
        assert!(st.want_n0(dev) && !st.want_n0(dev), "started once");
        assert_eq!(urls(st.listen()), ["https://mesh.example/", N0]);
        // ... and always when it is the mesh's only relay.
        let zero = State::new(Disk::new(Role::Host, vec![], vec![]));
        assert_eq!(urls(zero.listen()), [N0]);
        // `!n0` in the mesh relays: no fallback anywhere in the mesh
        let own = Disk::new(
            Role::Device,
            Relay::list("https://mesh.example/,!n0").unwrap(),
            vec![],
        );
        assert!(State::new(own).candidates().iter().all(|r| r.url != N0));
    }

    /// A stock relay pings us after 16-20 s of silence: that ping is the
    /// heartbeat there, and the NAT it keeps awake teaches nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_that_pings_is_the_heartbeat() {
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let srv = Server::spawn(cfg).await.unwrap();
        let r = Relay::parse(&format!("http://{}", srv.http_addr().unwrap()));
        let dir = std::env::temp_dir()
            .join(format!("irpush-hb-{}", hex::encode(rnd::<4>())));
        std::fs::create_dir_all(&dir).unwrap();
        let h = Node::create(dir.join("h"), rnd(), vec![r.unwrap()]).unwrap();
        let t = h.ticket(Role::Device).unwrap();
        let d = Node::join(dir.join("d"), rnd(), &t, vec![]).unwrap();
        let (h, d) = (std::sync::Arc::new(h), std::sync::Arc::new(d));
        for n in [h.clone(), d.clone()] {
            tokio::spawn(async move { n.run(|_, _, _| {}).await });
        }
        async fn until(d: &Node, f: fn(&State) -> bool, what: &str) {
            let t = Duration::from_secs(40);
            let wait = async {
                while !f(&d.lock()) {
                    sleep(Duration::from_millis(100)).await
                }
            };
            timeout(t, wait).await.expect(what)
        }
        until(&d, |st| !st.hosts().is_empty(), "paired").await;
        d.network(1); // a new session probes the heartbeat
        until(&d, |st| st.probe != 0, "probing").await;
        until(&d, |st| st.probe == 0, "the relay's ping ends it").await;
        assert!(d.lock().d.hb.is_empty(), "nothing learned");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn peer(
        role: Role,
        ek: x_wing::EncapsulationKey,
        psk: [u8; 32],
        relays: &str,
    ) -> Peer {
        Peer {
            ek,
            psk,
            role,
            ts: 0,
            route: vec![],
            relays: Relay::list(relays).unwrap(),
            mix: Mix::None,
            mesh: [0; 32],
        }
    }

    #[test]
    fn listen_gives_every_device_a_slot() {
        let list = |n: &str| {
            let l = (1..=4).map(|i| format!("https://{n}{i}.example/"));
            Relay::list(&l.collect::<Vec<_>>().join(",")).unwrap()
        };
        let mut d = Disk::new(Role::Host, list("m"), vec![]);
        let ek =
            || DecapsulationKey::from(rnd::<32>()).encapsulation_key().clone();
        let id = || iroh_base::SecretKey::from_bytes(&rnd()).public();
        let mut a = peer(Role::Device, ek(), rnd(), "");
        a.relays = list("a");
        d.peers.insert(id(), a);
        d.peers.insert(
            iroh_base::SecretKey::from_bytes(&rnd()).public(),
            peer(Role::Device, ek(), rnd(), "https://b.example/"),
        );
        let l = State::new(d).listen();
        assert!(
            l.iter().any(|r| r.url == "https://b.example/")
                && l.len() == MAX_LISTEN,
            "one device crowds out no other (n0: only on demand)"
        );
    }

    /// A host that introduced a and b knows their introduction PSK; once
    /// revoked (and helped by a relay that lies about senders) it must not be
    /// able to forge frames between them.
    #[test]
    fn introduced_pairs_rekey_beyond_the_introducer() {
        let dir = std::env::temp_dir()
            .join(format!("irpush-mix-{}", hex::encode(rnd::<4>())));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (
            Node::boot(
                dir.join("a"),
                rnd(),
                Disk::new(Role::Host, vec![], vec![]),
            )
            .unwrap(),
            Node::boot(
                dir.join("b"),
                rnd(),
                Disk::new(Role::Device, vec![], vec![]),
            )
            .unwrap(),
        );
        let (ia, ib, ek) = (a.id(), b.id(), |n: &Node| {
            n.lock().dk[0].encapsulation_key().clone()
        });
        let psk = proto::intro_psk(&rnd(), ia, ib);
        a.lock().d.peers.insert(ib, peer(Role::Device, ek(&b), psk, ""));
        b.lock().d.peers.insert(ia, peer(Role::Host, ek(&a), psk, ""));
        let got = Mutex::new(vec![]);
        let on = |_, _, d: &[u8]| got.lock().unwrap().push(d.to_vec());
        let forge = |kind, data: &[u8]| {
            proto::seal(
                &psk,
                Some(&ek(&b)),
                ia,
                ib,
                &proto::plain(kind, &rnd(), &app("x"), data).unwrap(),
            )
        };
        let pump = || {
            for _ in 0..4 {
                for (n, m) in [(&a, &b), (&b, &a)] {
                    let fs: Vec<_> =
                        n.outbox.lock().unwrap().drain(..).collect();
                    for (_, f) in fs {
                        m.handle("r", n.id(), &f, &on).unwrap();
                    }
                }
            }
        };
        b.handle("r", ia, &forge(Kind::Push, b"forged"), &on).unwrap();
        assert_eq!(
            got.lock().unwrap().len(),
            1,
            "before re-keying, the introducer's PSK works"
        );
        {
            let st = a.lock();
            a.send(&st, ib, Kind::Hello, &st.hello()).unwrap();
        } // as after an introduction
        pump();
        let (pa, pb) = (a.lock().d.peers[&ib].psk, b.lock().d.peers[&ia].psk);
        assert!(
            pa == pb
                && pa != psk
                && [&a, &b].iter().all(|n| n
                    .lock()
                    .d
                    .peers
                    .values()
                    .all(|p| p.mix == Mix::Fixed)),
            "mixed, confirmed"
        );
        b.handle("r", ia, &forge(Kind::Push, b"forged"), &on).unwrap();
        b.handle("r", ia, &forge(Kind::Relays, &[0; 10]), &on).unwrap();
        pump();
        assert_eq!(
            (a.lock().d.peers[&ib].psk, b.lock().d.peers[&ia].psk),
            (pa, pa)
        );
        a.push(ib, &app("x"), b"real").unwrap();
        pump();
        assert_eq!(
            *got.lock().unwrap(),
            [b"forged".to_vec(), b"real".to_vec()],
            "only the pair's own frames after re-keying"
        );
        assert!(
            store::load(&dir.join("b"), &b.kek).unwrap().peers[&ia].psk == pa,
            "persisted"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
