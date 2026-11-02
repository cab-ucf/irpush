//! Persistent state: one XChaCha20-Poly1305 file under a 32-byte platform key (KEK), replaced atomically.
use crate::proto::{EK, Id, Rd, lp, now, rnd};
use crate::relay::Relay;
use anyhow::{Context, Result, ensure};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit, Payload}};
use iroh_base::{EndpointId, SecretKey};
use std::{collections::HashMap, fs, io::Write, path::Path};
use x_wing::{EncapsulationKey, kem::KeyExport};

const VERSION: u8 = 7;
const AAD: &[u8] = b"irpush/state/7";

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Role { Device = 0, Host = 1 }
impl Role { pub(crate) fn of(b: u8) -> Self { if b == 1 { Role::Host } else { Role::Device } } }

pub(crate) struct Peer {
    pub ek: EncapsulationKey,
    pub psk: [u8; 32],
    pub role: Role,
    pub ts: u64,            // peer's key epoch (rejects rolled-back keys)
    pub route: Vec<u8>,     // iOS: svc | topic len | topic | APNs token
    pub relays: Vec<Relay>, // device: its app's default relays (hosts listen there)
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
}

impl Disk {
    pub fn new(role: Role, relays: Vec<Relay>, app: Vec<Relay>) -> Self {
        Self { sk: SecretKey::from_bytes(&rnd()), intro: rnd(), xw: rnd(), xw_prev: rnd(), rotated: now(), role, relays, relays_ver: 0, app, peers: HashMap::new(), revoked: vec![], hb: HashMap::new(), route: vec![], apns: vec![] }
    }

    fn enc(&self) -> Vec<u8> {
        let mut b = [&[VERSION][..], &self.sk.to_bytes(), &self.intro, &self.xw, &self.xw_prev, &self.rotated.to_le_bytes(), &[self.role as u8],
            &Relay::enc(&self.relays), &self.relays_ver.to_le_bytes(), &Relay::enc(&self.app), &lp(&self.route), &lp(&self.apns)].concat();
        b.extend((self.peers.len() as u32).to_le_bytes());
        for (id, p) in &self.peers {
            b.extend([&id.as_bytes()[..], &[p.role as u8], &p.ek.to_bytes(), &p.psk, &p.ts.to_le_bytes(), &lp(&p.route), &Relay::enc(&p.relays)].concat());
        }
        b.extend((self.revoked.len() as u32).to_le_bytes());
        for id in &self.revoked { b.extend(id.as_bytes()); }
        b.extend((self.hb.len() as u32).to_le_bytes());
        for (n, h) in &self.hb { b.extend([&n.to_le_bytes()[..], &h.to_le_bytes()].concat()); }
        b
    }

    fn dec(b: &[u8]) -> Result<Self> {
        let mut r = Rd(b);
        ensure!(r.u8()? == VERSION, "state version (re-join this node)");
        let (sk, intro, xw, xw_prev, rotated, role) = (SecretKey::from_bytes(&r.arr()?), r.arr()?, r.arr()?, r.arr()?, r.u64()?, Role::of(r.u8()?));
        let (relays, relays_ver, app) = (Relay::dec(&mut r)?, r.u64()?, Relay::dec(&mut r)?);
        let (route, apns) = (r.lp()?.to_vec(), r.lp()?.to_vec());
        let mut peers = HashMap::new();
        for _ in 0..r.u32()? {
            let (id, role, ek, psk, ts) = (r.id()?, Role::of(r.u8()?), r.ek()?, r.arr()?, r.u64()?);
            peers.insert(id, Peer { ek, psk, role, ts, route: r.lp()?.to_vec(), relays: Relay::dec(&mut r)? });
        }
        let revoked = (0..r.u32()?).map(|_| r.id()).collect::<Result<_>>()?;
        let hb = (0..r.u32()?).map(|_| Ok((r.u64()?, r.u32()?))).collect::<Result<_>>()?;
        ensure!(r.0.is_empty(), "trailing state bytes");
        Ok(Self { sk, intro, xw, xw_prev, rotated, role, relays, relays_ver, app, peers, revoked, hb, route, apns })
    }
}

const _: () = assert!(EK == 1216);

pub(crate) fn load(path: &Path, kek: &[u8; 32]) -> Result<Disk> {
    let b = fs::read(path).context("no state: create or join first")?;
    ensure!(b.len() > 24, "state truncated");
    let pt = XChaCha20Poly1305::new(kek.into()).decrypt(b[..24].into(), Payload { msg: &b[24..], aad: AAD }).ok().context("wrong key or corrupt state")?;
    Disk::dec(&pt)
}

pub(crate) fn save(path: &Path, kek: &[u8; 32], d: &Disk) -> Result<()> {
    let n: [u8; 24] = rnd();
    let ct = XChaCha20Poly1305::new(kek.into()).encrypt(&n.into(), Payload { msg: &d.enc(), aad: AAD }).expect("in-memory AEAD");
    let tmp = path.with_extension("tmp");
    write_private(&tmp, &[&n[..], &ct].concat())?;
    Ok(fs::rename(tmp, path)?) // atomic: the iOS extension may be reading
}

/// Delivered-id log shared by an app and its iOS extension: each push is delivered once on any path.
/// Holds ids only (random), no content.
pub(crate) fn first_delivery(path: &Path, id: &Id) -> Result<bool> {
    let p = path.with_extension("seen");
    let b = fs::read(&p).unwrap_or_default();
    if b.as_chunks::<16>().0.contains(id) { return Ok(false) }
    if b.len() >= 16 * 4096 { write_private(&p, &[&b[b.len() - 16 * 1023..], id].concat())?; } else { open_private(&p, true)?.write_all(id)?; }
    Ok(true)
}

fn open_private(p: &Path, append: bool) -> Result<fs::File> {
    #[cfg(unix)] use std::os::unix::fs::OpenOptionsExt;
    let mut o = fs::OpenOptions::new();
    if append { o.append(true).create(true); } else { o.write(true).create(true).truncate(true); }
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
        d.peers.insert(id, Peer { ek: ek.clone(), psk: rnd(), role: Role::Device, ts: 9, route: vec![1, 2], relays: Relay::list("https://b.example/").unwrap() });
        d.hb.insert(7, 240);
        save(&p, &kek, &d).unwrap();
        let e = load(&p, &kek).unwrap();
        assert_eq!(e.enc(), d.enc());
        assert!(load(&p, &rnd()).is_err());
        assert!(first_delivery(&p, &[1; 16]).unwrap() && !first_delivery(&p, &[1; 16]).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
