//! A host's own relay: a desktop instead of a VPS. Members only. Its
//! certificate is self-signed and pinned in the address its devices get
//! (`https://IP:PORT/#sha256=…`): no domain, no certificate authority. It is
//! reached through a port the router maps (UPnP, PCP, NAT-PMP), a global IPv6
//! address, or the LAN; where none reaches (carrier-grade NAT), devices use the
//! mesh's other relays, n0's last.
use crate::{Node, Relay, relay, store::write_private};
use anyhow::{Context, Result};
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRequest, RelayConfig, Server,
    ServerConfig, TlsConfig,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::{num::NonZeroU16, path::Path, sync::Arc, sync::Weak, time::Duration};
use tracing::{info, warn};

/// The relay, running while this lives.
pub struct Served {
    pub addr: SocketAddr,
    pub pin: [u8; 32],
    _server: Server,
}

/// Serve on `bind` (e.g. `[::]:7843`). Its certificate and key live in `dir`.
pub async fn serve(
    node: &Arc<Node>,
    dir: &Path,
    bind: SocketAddr,
) -> Result<Served> {
    let (cert, key) = identity(dir)?;
    let pin = Sha256::digest(&cert).into();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key).into();
    let tls = rustls::ServerConfig::builder_with_provider(crate::pq())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.into()], key)?;
    // Plain HTTP (captive-portal probes) on loopback only.
    let mut rc = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    let cert = CertConfig::Manual { server_config: tls };
    rc.tls = Some(TlsConfig::new(bind, cert));
    rc.access = Arc::new(Members(Arc::downgrade(node)));
    // Its members keep their own heartbeats, up to 2 h: no 15 s pings.
    #[cfg(feature = "relay-ping")]
    {
        rc.ping_interval = Duration::from_secs(130 * 60);
    }
    let mut cfg = ServerConfig::default();
    cfg.relay = Some(rc);
    let server = Server::spawn(cfg).await?;
    let addr = server.https_addr().context("no https address")?;
    node.set_served(addr.port(), pin);
    info!(%addr, "serving this host's relay");
    Ok(Served { addr, pin, _server: server })
}

/// The relay's certificate and PKCS#8 key (DER), made once.
fn identity(dir: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let (c, k) = (dir.join("relay.crt"), dir.join("relay.key"));
    if !c.exists() || !k.exists() {
        let ck = rcgen::generate_simple_self_signed(vec!["irpush".into()])?;
        write_private(&k, &ck.signing_key.serialize_der())?;
        write_private(&c, ck.cert.der())?;
    }
    Ok((std::fs::read(c)?, std::fs::read(k)?))
}

/// Only this node, its peers, and (while a ticket is unused) its holder.
#[derive(Debug)]
struct Members(Weak<Node>);

impl AccessControl for Members {
    async fn on_connect(&self, r: &ClientRequest) -> Access {
        match self.0.upgrade().is_some_and(|n| n.admits(&r.endpoint_id())) {
            true => Access::Allow,
            false => Access::Deny { reason: None },
        }
    }
}

/// Keep this relay first in the mesh relays, at the addresses that reach it:
/// the port the router maps, a global IPv6 address, the LAN. Checked when the
/// mapping changes and every 30 minutes; the router is asked only then, never
/// in a loop. A host already listed stays where it is. Runs forever.
pub async fn announce(node: Arc<Node>, port: u16, pin: [u8; 32]) {
    let cfg = portmapper::Config {
        protocol: portmapper::Protocol::Tcp,
        ..Default::default()
    };
    let pm = portmapper::Client::new(cfg);
    if let Some(p) = NonZeroU16::new(port) {
        pm.update_local_port(p);
    }
    let mut mapped = pm.watch_external_address();
    loop {
        pm.procure_mapping(); // no-op while a mapping holds
        let v4 = mapped.borrow_and_update().map(SocketAddr::V4);
        let ours: Vec<Relay> = [v4, ip(true), ip(false)]
            .into_iter()
            .flatten()
            .map(|a| Relay {
                url: format!("https://{}/", SocketAddr::new(a.ip(), port)),
                pin: Some(pin),
            })
            .collect();
        let cur = node.relays();
        let listed: Vec<_> =
            cur.iter().filter(|r| r.pin == Some(pin)).collect();
        if !ours.is_empty() && listed.into_iter().ne(ours.iter()) {
            let rest = cur.into_iter().filter(|r| r.pin != Some(pin));
            let l = relay::dedup(ours.into_iter().chain(rest));
            info!(relays = %Relay::show(&l), "this host's relay announced");
            if let Err(e) = node.set_relays(l) {
                warn!("announcing this host's relay: {e:#}")
            }
        }
        tokio::select! {
            r = mapped.changed() => if r.is_err() { return },
            _ = tokio::time::sleep(Duration::from_secs(1800)) => {}
        }
    }
}

/// This machine's address toward the internet (no packet is sent): a global
/// IPv6 one, or (`v6` false) its IPv4 one, the LAN's behind a router.
fn ip(v6: bool) -> Option<SocketAddr> {
    let (bind, to) = match v6 {
        true => ("[::]:0", "[2606:4700:4700::1111]:443"),
        false => ("0.0.0.0:0", "1.1.1.1:443"),
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(to).ok()?;
    let a = s.local_addr().ok()?;
    let ok = match a.ip() {
        IpAddr::V6(i) => {
            let s0 = i.segments()[0];
            !i.is_loopback() && s0 & 0xffc0 != 0xfe80 && s0 & 0xfe00 != 0xfc00
        }
        IpAddr::V4(i) => !i.is_loopback() && !i.is_link_local(),
    };
    ok.then_some(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Role, app, proto::rnd};
    use iroh_relay::client::ClientBuilder;

    type Rx = tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>;

    /// A host serving its own relay, the mesh's only one, and a device paired
    /// through it.
    async fn mesh() -> (std::path::PathBuf, Arc<Node>, Arc<Node>, Served, Rx) {
        let tmp = format!("irpush-serve-{}", hex::encode(rnd::<4>()));
        let dir = std::env::temp_dir().join(tmp);
        std::fs::create_dir_all(&dir).unwrap();
        let h = Arc::new(Node::create(dir.join("h"), rnd(), vec![]).unwrap());
        let s = serve(&h, &dir, ([127, 0, 0, 1], 0).into()).await.unwrap();
        let mine =
            Relay { url: format!("https://{}/", s.addr), pin: Some(s.pin) };
        let only = vec![mine, Relay::parse(relay::NO_N0).unwrap()];
        h.set_relays(only).unwrap();
        let t = h.ticket(Role::Device).unwrap();
        let d = Arc::new(Node::join(dir.join("d"), rnd(), &t, vec![]).unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let hh = h.clone();
        tokio::spawn(async move { hh.run(|_, _, _| {}).await });
        let dd = d.clone();
        let on = move |_, _, b: &[u8]| drop(tx.send(b.to_vec()));
        tokio::spawn(async move { dd.run(on).await });
        let paired = async {
            while !d.has(&h.id()) {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
        };
        let t = Duration::from_secs(20);
        tokio::time::timeout(t, paired).await.expect("paired through it");
        (dir, h, d, s, rx)
    }

    /// A host's own relay: a device pairs and is pushed to through it, its
    /// certificate pinned; then a stranger is refused, and so is a member who
    /// was given another pin.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hosts_own_relay_serves_its_mesh_only() {
        let (dir, h, d, s, mut rx) = mesh().await;
        h.push(d.id(), &app("x"), b"hi").unwrap();
        let t = Duration::from_secs(20);
        let got = tokio::time::timeout(t, rx.recv()).await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"hi"[..]));

        let url: iroh_base::RelayUrl =
            format!("https://{}/", s.addr).parse().unwrap();
        let dial = |sk, pin| {
            let dns = iroh_dns::dns::DnsResolver::new();
            let tls = crate::pinned(pin).unwrap();
            let b = ClientBuilder::new(url.clone(), sk, dns);
            async move { b.tls_client_config(tls).connect().await }
        };
        let stranger = iroh_base::SecretKey::from_bytes(&rnd());
        assert!(dial(stranger, s.pin).await.is_err(), "members only");
        let member = d.lock().d.sk.clone();
        assert!(dial(member, [0; 32]).await.is_err(), "another certificate");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Built against the patched relay (`make desktop`): a member that stays
    /// silent is not pinged after 16-20 s, so its heartbeat probe runs on.
    #[cfg(feature = "relay-ping")]
    #[tokio::test(flavor = "multi_thread")]
    async fn its_members_are_left_to_sleep() {
        let (dir, _h, d, _s, _rx) = mesh().await;
        d.network(1); // a new session probes the heartbeat
        let probing = async {
            while d.lock().probe == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
        };
        let t = Duration::from_secs(20);
        tokio::time::timeout(t, probing).await.expect("probing");
        tokio::time::sleep(Duration::from_secs(25)).await;
        assert!(d.lock().probe != 0, "a relay ping ended the probe");
        let _ = std::fs::remove_dir_all(dir);
    }
}
