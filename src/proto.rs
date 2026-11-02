//! Wire format and frame crypto. Every frame has one size on every path (relay, APNs).
//!
//! frame = ct (1120) || ChaCha20-Poly1305(key, 0-nonce, plaintext (HDR + BODY))
//! KEM mode: ct = X-Wing encapsulation to the recipient; key = HKDF(psk, ss || ct, label || from || to).
//! PSK mode (pairing; Hello resync only): ct = random; key = HKDF(psk, ct, label || from || to).
//! Keys are unique per frame (fresh ct), so the zero nonce is never reused.
use anyhow::{Context, Result, ensure};
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use iroh_base::EndpointId;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use x_wing::{CIPHERTEXT_SIZE as CT, DecapsulationKey, EncapsulationKey, kem::{Decapsulate, Encapsulate}};

pub use x_wing::ENCAPSULATION_KEY_SIZE as EK;

/// Max push payload. A base64 frame plus APNs JSON stays under Apple's 4 KiB.
pub const BODY: usize = 1536;
pub(crate) const HDR: usize = 1 + 16 + 16 + 8 + 2; // kind | msg id | app | unix time | len
/// Frame size on the wire (2715 B).
pub const FRAME: usize = CT + HDR + BODY + 16;
const MAX_AGE: u64 = 25 * 3600; // APNs keeps a notification up to 24 h
const MAX_SKEW: u64 = 3600;

/// App address on a device: hash of its stable name (bundle id / package name).
pub type App = [u8; 16];
pub(crate) type Id = [u8; 16];

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub(crate) enum Kind { Push = 1, Ack, Hello, Pair, Intro, Revoke, Relays, Echo }

impl TryFrom<u8> for Kind {
    type Error = anyhow::Error;
    fn try_from(b: u8) -> Result<Self> {
        use Kind::*;
        Ok(match b { 1 => Push, 2 => Ack, 3 => Hello, 4 => Pair, 5 => Intro, 6 => Revoke, 7 => Relays, 8 => Echo, _ => anyhow::bail!("kind {b}") })
    }
}

pub(crate) struct Msg<'a> { pub kind: Kind, pub id: Id, pub app: App, pub data: &'a [u8] }

pub(crate) fn rnd<const N: usize>() -> [u8; N] { let mut b = [0; N]; getrandom::fill(&mut b).expect("OS RNG"); b }
pub(crate) fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) }
pub(crate) fn tag(b: &[u8]) -> [u8; 8] { Sha256::digest(b)[..8].try_into().unwrap() }
pub(crate) fn lp(b: &[u8]) -> Vec<u8> { [&(b.len() as u16).to_le_bytes()[..], b].concat() }
pub fn app(name: &str) -> App { Sha256::digest(name)[..16].try_into().unwrap() }

fn kdf(salt: &[u8], ikm: &[&[u8]], info: &[&[u8]]) -> [u8; 32] {
    let mut k = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), &ikm.concat()).expand_multi_info(info, &mut k).expect("32 B is a valid HKDF length");
    k
}

pub(crate) fn pair_psk(s: &[u8; 32], a: EndpointId, b: EndpointId) -> [u8; 32] {
    let (a, b) = if a.as_bytes() < b.as_bytes() { (a, b) } else { (b, a) };
    kdf(s, &[], &[b"irpush/4/psk", a.as_bytes(), b.as_bytes()])
}

/// Introduction PSK for a and b, from the introducing host's secret (idempotent across retries).
pub(crate) fn intro_psk(host_secret: &[u8; 32], a: EndpointId, b: EndpointId) -> [u8; 32] {
    let (a, b) = if a.as_bytes() < b.as_bytes() { (a, b) } else { (b, a) };
    kdf(host_secret, &[], &[b"irpush/4/intro", a.as_bytes(), b.as_bytes()])
}

fn cipher(psk: &[u8; 32], ss: Option<&[u8]>, ct: &[u8], from: EndpointId, to: EndpointId) -> ChaCha20Poly1305 {
    let (label, ikm): (&[u8], [&[u8]; 2]) = match ss { Some(ss) => (b"irpush/4/kem", [ss, ct]), None => (b"irpush/4/psk-frame", [&[], ct]) };
    ChaCha20Poly1305::new(&kdf(psk, &ikm, &[label, from.as_bytes(), to.as_bytes()]).into())
}

/// Plaintext: header + data, zero-padded to a constant size (hides kind and length).
pub(crate) fn plain(kind: Kind, id: &Id, app: &App, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() <= BODY, "payload > {BODY} bytes");
    let mut p = [&[kind as u8][..], id, app, &now().to_le_bytes(), &(data.len() as u16).to_le_bytes(), data].concat();
    p.resize(HDR + BODY, 0);
    Ok(p)
}

/// Parse and check freshness (bounds replay to the dedupe window).
pub(crate) fn parse(p: &[u8]) -> Result<Msg<'_>> {
    ensure!(p.len() == HDR + BODY, "plaintext size");
    let ts = u64::from_le_bytes(p[33..41].try_into()?);
    let t = now();
    ensure!(ts + MAX_AGE >= t && ts <= t + MAX_SKEW, "stale or future frame");
    let n = u16::from_le_bytes([p[41], p[42]]) as usize;
    Ok(Msg { kind: p[0].try_into()?, id: p[1..17].try_into()?, app: p[17..33].try_into()?, data: p.get(HDR..HDR + n).context("len")? })
}

/// `ek`: Some = KEM mode to the recipient's key, None = PSK mode.
pub(crate) fn seal(psk: &[u8; 32], ek: Option<&EncapsulationKey>, from: EndpointId, to: EndpointId, pt: &[u8]) -> Vec<u8> {
    let (ct, ss) = match ek { Some(ek) => { let (c, s) = ek.encapsulate(); (c.to_vec(), Some(s.to_vec())) } None => (rnd::<CT>().to_vec(), None) };
    let body = cipher(psk, ss.as_deref(), &ct, from, to).encrypt(&[0; 12].into(), pt).expect("in-memory AEAD");
    [ct, body].concat()
}

pub(crate) fn open_kem(dks: &[DecapsulationKey], psk: &[u8; 32], from: EndpointId, to: EndpointId, f: &[u8]) -> Option<Vec<u8>> {
    if f.len() != FRAME { return None }
    let (ct, body) = f.split_at(CT);
    dks.iter().find_map(|dk| cipher(psk, Some(&dk.decapsulate(ct.try_into().ok()?)), ct, from, to).decrypt(&[0; 12].into(), body).ok())
}

pub(crate) fn open_psk(psk: &[u8; 32], from: EndpointId, to: EndpointId, f: &[u8]) -> Option<Vec<u8>> {
    if f.len() != FRAME { return None }
    let (ct, body) = f.split_at(CT);
    cipher(psk, None, ct, from, to).decrypt(&[0; 12].into(), body).ok()
}

/// Bounds-checked reader for untrusted bytes.
pub(crate) struct Rd<'a>(pub &'a [u8]);
impl<'a> Rd<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> { ensure!(self.0.len() >= n, "truncated"); let (a, b) = self.0.split_at(n); self.0 = b; Ok(a) }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N]> { Ok(self.take(N)?.try_into()?) }
    pub fn u8(&mut self) -> Result<u8> { Ok(self.arr::<1>()?[0]) }
    pub fn u32(&mut self) -> Result<u32> { Ok(u32::from_le_bytes(self.arr()?)) }
    pub fn u64(&mut self) -> Result<u64> { Ok(u64::from_le_bytes(self.arr()?)) }
    pub fn id(&mut self) -> Result<EndpointId> { Ok(EndpointId::from_bytes(&self.arr()?)?) }
    pub fn ek(&mut self) -> Result<EncapsulationKey> { Ok(EncapsulationKey::try_from(self.take(EK)?)?) }
    pub fn lp(&mut self) -> Result<&'a [u8]> { let n = u16::from_le_bytes(self.arr()?) as usize; self.take(n) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::SecretKey;
    use x_wing::kem::Decapsulator;

    fn ids() -> (EndpointId, EndpointId) { (SecretKey::from_bytes(&rnd()).public(), SecretKey::from_bytes(&rnd()).public()) }

    #[test]
    fn kem_roundtrip_and_binding() {
        let (a, b) = ids();
        let (dk, psk) = (DecapsulationKey::from(rnd::<32>()), rnd::<32>());
        let pt = plain(Kind::Push, &rnd(), &app("x"), b"hi").unwrap();
        let f = seal(&psk, Some(dk.encapsulation_key()), a, b, &pt);
        assert_eq!(f.len(), FRAME);
        assert_eq!(open_kem(std::slice::from_ref(&dk), &psk, a, b, &f).unwrap(), pt);
        assert!(open_kem(std::slice::from_ref(&dk), &psk, b, a, &f).is_none(), "direction bound");
        assert!(open_kem(std::slice::from_ref(&dk), &rnd(), a, b, &f).is_none(), "psk bound");
        assert!(open_kem(&[DecapsulationKey::from(rnd::<32>())], &psk, a, b, &f).is_none(), "kem bound");
        assert!(open_psk(&psk, a, b, &f).is_none(), "modes separated");
        let mut t = f.clone();
        t[FRAME - 1] ^= 1;
        assert!(open_kem(&[dk], &psk, a, b, &t).is_none(), "tamper");
    }

    #[test]
    fn freshness_and_size() {
        let mut p = plain(Kind::Hello, &rnd(), &[0; 16], &[7; 3]).unwrap();
        let m = parse(&p).unwrap();
        assert!(m.kind == Kind::Hello && m.data == [7; 3]);
        p[33..41].copy_from_slice(&(now() - MAX_AGE - 10).to_le_bytes());
        assert!(parse(&p).is_err());
        assert!(plain(Kind::Push, &rnd(), &[0; 16], &[0; BODY + 1]).is_err());
    }
}
