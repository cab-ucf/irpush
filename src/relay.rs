//! Push relay addresses: `url` (an older `url#token` is read as `url`: relays are open).
use crate::proto::{Rd, lp};
use anyhow::{Result, ensure};
use iroh_base::RelayUrl;

/// n0's public relay: always the last-resort fallback, so connectivity never depends on one relay.
/// Frames stay end-to-end encrypted; n0 sees endpoint ids, IPs and timing. Its ~15 s pings cost
/// Android battery while in use.
pub const N0: &str = "https://use1-1.relay.n0.iroh.link./";
/// In the mesh relays (`irpush DIR relays "https://you.example,!n0"`): never fall back to n0.
/// Hosts propagate it to every member, so the whole mesh stays on its own infrastructure.
pub const NO_N0: &str = "!n0";

#[derive(Clone, PartialEq, Debug)]
pub struct Relay { pub url: String }

impl Relay {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s == NO_N0 { return Ok(Self { url: NO_N0.into() }) }
        let u = s.split('#').next().unwrap_or_default();
        Ok(Self { url: u.parse::<RelayUrl>()?.to_string() })
    }
    /// Comma-separated, preference order.
    pub fn list(s: &str) -> Result<Vec<Self>> { s.split(',').filter(|x| !x.trim().is_empty()).map(Self::parse).collect() }
    pub fn show(l: &[Self]) -> String { l.iter().map(|r| r.url.as_str()).collect::<Vec<_>>().join(",") }
    pub(crate) fn n0() -> Self { Self { url: N0.into() } }
    pub(crate) fn enc(l: &[Self]) -> Vec<u8> { lp(Self::show(l).as_bytes()) }
    pub(crate) fn dec(r: &mut Rd) -> Result<Vec<Self>> { Self::list(std::str::from_utf8(r.lp()?)?) }
    /// Relays a *device* may ask hosts to dial: https with a DNS name only (no IP literals, so a member
    /// cannot point hosts at their LAN).
    pub(crate) fn public(&self) -> Result<()> {
        let u = url::Url::parse(&self.url)?;
        ensure!(u.scheme() == "https" && matches!(u.host(), Some(url::Host::Domain(d)) if d.contains('.')), "device relays must be https://<domain>");
        Ok(())
    }
}

pub fn is_n0(url: &str) -> bool { url == N0 }

/// The n0 fallback unless the list opts out of it.
pub(crate) fn fallback(l: &[Relay]) -> Option<Relay> { (!l.iter().any(|r| r.url == NO_N0)).then(Relay::n0) }

pub(crate) fn dedup(l: impl IntoIterator<Item = Relay>) -> Vec<Relay> {
    let mut out: Vec<Relay> = vec![];
    for r in l { if !out.iter().any(|x| x.url == r.url) { out.push(r) } }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_show_and_public() {
        let l = Relay::list(&format!("https://a.example/#{}, http://10.0.0.1:3340", "ab".repeat(32))).unwrap();
        assert_eq!(Relay::list(&Relay::show(&l)).unwrap(), l);
        assert!(l[0].public().is_ok());
        assert!(l[1].public().is_err());
        assert!(Relay::parse("https://192.168.1.1/").unwrap().public().is_err());
        assert_eq!(Relay::parse("https://a.example/#old").unwrap(), l[0], "a token is dropped");
        let o = Relay::list("https://a.example/,!n0").unwrap();
        assert!(fallback(&o).is_none() && fallback(&l).is_some() && o[1].public().is_err());
        assert_eq!(Relay::list(&Relay::show(&o)).unwrap(), o);
    }
}
