//! Persistent state: one XChaCha20-Poly1305 file under a 32-byte platform key (KEK), replaced atomically.
use crate::proto::{EK, Id, MAX_AGE, Rd, lp, now, rnd};
use crate::relay::Relay;
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit, Payload}};
use iroh_base::{EndpointId, SecretKey};
use std::{collections::HashMap, fs, io::{Read, Seek, Write}, path::Path};
use zeroize::Zeroize;
use x_wing::{EncapsulationKey, kem::KeyExport};

const VERSION: u8 = 10; // 9 had either Peer::mix or Peer::mesh (unreleased); 8: neither
const AAD: &[u8] = b"irpush/state/10";
const AAD8: &[u8] = b"irpush/state/8"; // read, then rewritten as 10: one mesh, tagged 0

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Role { Device = 0, Host = 1 }
impl Role { pub(crate) fn of(b: u8) -> Self { if b == 1 { Role::Host } else { Role::Device } } }

impl Drop for Peer {
    fn drop(&mut self) { self.psk.zeroize(); match &mut self.mix { Mix::Sent(c) => c.zeroize(), Mix::Done(p, c) => { p.zeroize(); c.zeroize() } Mix::None | Mix::Fixed => {} } }
}

/// Re-keying a pair between themselves (`Kind::Key`): None (not started, or an old peer), Sent(ours),
/// Done(previous PSK, ours): mixed, the previous PSK still opens their frames until they use the new
/// one; Fixed: only the mixed PSK.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Mix { None, Sent([u8; 32]), Done([u8; 32], [u8; 32]), Fixed }
impl Mix {
    fn enc(&self) -> Vec<u8> { match self { Mix::None => vec![0], Mix::Sent(c) => [&[1][..], c].concat(), Mix::Done(p, c) => [&[2][..], p, c].concat(), Mix::Fixed => vec![3] } }
    fn dec(r: &mut Rd) -> Result<Self> { Ok(match r.u8()? { 0 => Mix::None, 1 => Mix::Sent(r.arr()?), 2 => Mix::Done(r.arr()?, r.arr()?), 3 => Mix::Fixed, m => bail!("mix {m}") }) }
}
impl Drop for Disk { fn drop(&mut self) { self.intro.zeroize(); self.xw.zeroize(); self.xw_prev.zeroize(); self.apns.zeroize() } }

pub(crate) struct Peer {
    pub ek: EncapsulationKey,
    pub psk: [u8; 32],
    pub role: Role,
    pub ts: u64,            // peer's key epoch (rejects rolled-back keys)
    pub route: Vec<u8>,     // iOS: APNs routes, one per app (apns::merge)
    pub relays: Vec<Relay>, // device: the relays it uses (hosts listen there)
    pub mix: Mix,
    pub mesh: [u8; 32],     // device: the host whose ticket brought this peer in (scopes revokes)
}

pub(crate) struct Disk {
    pub sk: SecretKey,      // relay identity (ed25519), used only to authenticate to relays
    pub intro: [u8; 32],    // hosts: derives introduction PSKs (separate key per purpose)
    pub xw: [u8; 32],
    pub xw_prev: [u8; 32],
    pub rotated: u64,
    pub role: Role,
    pub relays: Vec<Relay>, // mesh relays, set by hosts
    pub relays_ver: u64,
    pub app: Vec<Relay>,    // device: its app's default relays
    pub peers: HashMap<EndpointId, Peer>,
    pub revoked: Vec<EndpointId>,
    pub hb: HashMap<u64, u32>, // learned heartbeat secs per network (| SETTLED)
    pub route: Vec<u8>,     // ours (iOS devices)
    pub apns: Vec<u8>,      // hosts: "KEYID TEAMID\n<p8 PEM>"
    pub home: [u8; 32],     // device: the mesh whose hosts set our relays (the first joined)
}

impl Disk {
    pub fn new(role: Role, relays: Vec<Relay>, app: Vec<Relay>) -> Self {
        Self { sk: SecretKey::from_bytes(&rnd()), intro: rnd(), xw: rnd(), xw_prev: rnd(), rotated: now(), role, relays, relays_ver: 0, app, peers: HashMap::new(), revoked: vec![], hb: HashMap::new(), route: vec![], apns: vec![], home: [0; 32] }
    }

    fn enc(&self) -> Vec<u8> {
        let mut b = [&[VERSION][..], &self.sk.to_bytes(), &self.intro, &self.xw, &self.xw_prev, &self.rotated.to_le_bytes(), &[self.role as u8],
            &Relay::enc(&self.relays), &self.relays_ver.to_le_bytes(), &Relay::enc(&self.app), &lp(&self.route), &lp(&self.apns), &self.home].concat();
        b.extend((self.peers.len() as u32).to_le_bytes());
        for (id, p) in &self.peers {
            b.extend([&id.as_bytes()[..], &[p.role as u8], &p.ek.to_bytes(), &p.psk, &p.ts.to_le_bytes(), &lp(&p.route), &Relay::enc(&p.relays), &p.mix.enc(), &p.mesh].concat());
        }
        b.extend((self.revoked.len() as u32).to_le_bytes());
        for id in &self.revoked { b.extend(id.as_bytes()); }
        b.extend((self.hb.len() as u32).to_le_bytes());
        for (n, h) in &self.hb { b.extend([&n.to_le_bytes()[..], &h.to_le_bytes()].concat()); }
        b
    }

    fn dec(b: &[u8]) -> Result<Self> {
        let mut r = Rd(b);
        let v = r.u8()?;
        ensure!(v == VERSION || v == 8, "state version (re-join this node)");
        let (sk, intro, xw, xw_prev, rotated, role) = (SecretKey::from_bytes(&r.arr()?), r.arr()?, r.arr()?, r.arr()?, r.u64()?, Role::of(r.u8()?));
        let (relays, relays_ver, app) = (Relay::dec(&mut r)?, r.u64()?, Relay::dec(&mut r)?);
        let (route, apns) = (r.lp()?.to_vec(), r.lp()?.to_vec());
        let home = if v == 8 { [0; 32] } else { r.arr()? };
        let mut peers = HashMap::new();
        for _ in 0..r.u32()? {
            let (id, role, ek, psk, ts) = (r.id()?, Role::of(r.u8()?), r.ek()?, r.arr()?, r.u64()?);
            let (route, relays) = (r.lp()?.to_vec(), Relay::dec(&mut r)?);
            let (mix, mesh) = if v == 8 { (Mix::None, [0; 32]) } else { (Mix::dec(&mut r)?, r.arr()?) };
            peers.insert(id, Peer { ek, psk, role, ts, route, relays, mix, mesh });
        }
        let revoked = (0..r.u32()?).map(|_| r.id()).collect::<Result<_>>()?;
        let hb = (0..r.u32()?).map(|_| Ok((r.u64()?, r.u32()?))).collect::<Result<_>>()?;
        ensure!(r.0.is_empty(), "trailing state bytes");
        Ok(Self { sk, intro, xw, xw_prev, rotated, role, relays, relays_ver, app, peers, revoked, hb, route, apns, home })
    }
}

const _: () = assert!(EK == 1216);

pub(crate) fn load(path: &Path, kek: &[u8; 32]) -> Result<Disk> {
    let b = fs::read(path).context("no state: create or join first")?;
    ensure!(b.len() > 24, "state truncated");
    let c = XChaCha20Poly1305::new(kek.into());
    let pt = [AAD, AAD8].iter().find_map(|aad| c.decrypt(b[..24].into(), Payload { msg: &b[24..], aad }).ok()).context("wrong key or corrupt state")?;
    Disk::dec(&pt)
}

pub(crate) fn save(path: &Path, kek: &[u8; 32], d: &Disk) -> Result<()> {
    let n: [u8; 24] = rnd();
    let ct = XChaCha20Poly1305::new(kek.into()).encrypt(&n.into(), Payload { msg: &d.enc(), aad: AAD }).expect("in-memory AEAD");
    let tmp = path.with_extension(format!("tmp{}", hex::encode(rnd::<4>()))); // one per writer: never interleaved
    let r = write_private(&tmp, &[&n[..], &ct].concat()).and_then(|_| Ok(fs::rename(&tmp, path)?)); // atomic: the iOS extension may be reading
    if r.is_err() { let _ = fs::remove_file(tmp); }
    r
}

const DELIVERED: usize = 8192; // records kept at most; trimmed to half, oldest first

/// Delivered-id log shared by an app and its iOS extension: each push is delivered once on any path.
/// floor (u64) | (frame time (u64) | id)*: ids only (random), no content. Ids stay for the freshness
/// window; when there are too many, the oldest go and `floor` rises past them: a push sealed at or
/// before the floor counts as delivered (hosts re-seal retransmits, so only replays are that old).
pub(crate) fn first_delivery(path: &Path, id: &Id, ts: u64) -> Result<bool> {
    let mut f = open_private(&path.with_extension("delivered"), true)?;
    f.lock()?; // the app and its iOS extension race here: check-and-record is one step
    let mut b = vec![];
    f.read_to_end(&mut b)?;
    let floor = b.get(..8).map_or(0, |x| u64::from_le_bytes(x.try_into().unwrap()));
    let mut recs = b.get(8..).unwrap_or_default().as_chunks::<24>().0.to_vec();
    if ts <= floor || recs.iter().any(|r| r[8..] == id[..]) { return Ok(false) }
    recs.push([&ts.to_le_bytes()[..], id].concat().try_into().unwrap());
    let ts_of = |r: &[u8; 24]| u64::from_le_bytes(r[..8].try_into().unwrap());
    let floor = if recs.len() > DELIVERED {
        recs.retain(|r| ts_of(r) + MAX_AGE + 3600 >= now()); // older ones fail freshness anyway
        recs.sort_by_key(ts_of);
        let cut = recs.len().saturating_sub(DELIVERED / 2);
        recs.drain(..cut).map(|r| ts_of(&r)).max().map_or(floor, |m| m.max(floor))
    } else if b.len() >= 8 { return Ok(f.write_all(&recs[recs.len() - 1]).map(|_| true)?) } else { floor };
    f.set_len(0)?;
    f.rewind()?;
    f.write_all(&[&floor.to_le_bytes()[..], recs.as_flattened()].concat())?;
    Ok(true)
}

fn open_private(p: &Path, rw: bool) -> Result<fs::File> {
    #[cfg(unix)] use std::os::unix::fs::OpenOptionsExt;
    let mut o = fs::OpenOptions::new();
    if rw { o.read(true).write(true).create(true); } else { o.write(true).create(true).truncate(true); }
    #[cfg(unix)] o.mode(0o600);
    Ok(o.open(p)?)
}

/// Write a 0600 file and fsync it.
pub fn write_private(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = open_private(p, false)?;
    f.write_all(b)?;
    Ok(f.sync_all()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x_wing::{DecapsulationKey, kem::Decapsulator};

    #[test]
    fn roundtrip_and_wrong_key() {
        let dir = std::env::temp_dir().join(format!("irpush-store-{}", hex::encode(rnd::<4>())));
        fs::create_dir_all(&dir).unwrap();
        let (p, kek) = (dir.join("state"), rnd::<32>());
        let mut d = Disk::new(Role::Host, Relay::list("https://a.example/").unwrap(), vec![]);
        let id = SecretKey::from_bytes(&rnd()).public();
        let dk = DecapsulationKey::from(rnd::<32>());
        let ek = dk.encapsulation_key();
        d.peers.insert(id, Peer { ek: ek.clone(), psk: rnd(), role: Role::Device, ts: 9, route: vec![1, 2], relays: Relay::list("https://b.example/").unwrap(), mix: Mix::Done(rnd(), rnd()), mesh: [3; 32] });
        d.home = [4; 32];
        d.hb.insert(7, 240);
        save(&p, &kek, &d).unwrap();
        let e = load(&p, &kek).unwrap();
        assert_eq!(e.enc(), d.enc());
        assert!(load(&p, &rnd()).is_err());
        let t = now();
        assert!(first_delivery(&p, &[1; 16], t).unwrap() && !first_delivery(&p, &[1; 16], t).unwrap());
        for i in 0..DELIVERED as u64 { assert!(first_delivery(&p, &rnd(), t + i).unwrap()); } // trims once, oldest first
        assert!(!first_delivery(&p, &rnd(), t).unwrap(), "older than the trimmed ids: a replay");
        assert!(!first_delivery(&p, &[1; 16], t).unwrap() && first_delivery(&p, &rnd(), t + DELIVERED as u64).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
