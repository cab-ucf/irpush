//! End to end over an in-process relay: pairing (with a late host), mesh introduction, pushes from
//! two hosts, offline queueing, revocation, refusal to overwrite an identity, and one node shared by
//! several apps over the local socket.
use iroh_base::EndpointId;
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use irpush::{App, Local, Node, Relay, Role, app, local, random32};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle, time::{sleep, timeout}};

type Rx = mpsc::UnboundedReceiver<(EndpointId, App, Vec<u8>)>;

async fn relay() -> (Server, Relay) {
    let mut cfg = ServerConfig::default();
    cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
    let s = Server::spawn(cfg).await.unwrap();
    let url = format!("http://{}", s.http_addr().unwrap());
    (s, Relay::parse(&url).unwrap())
}

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("irpush-test-{}", hex::encode(&random32()[..6])));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(n: Arc<Node>) -> (JoinHandle<()>, Rx) {
    let (tx, rx) = mpsc::unbounded_channel();
    (tokio::spawn(async move { let _ = n.run(move |f, a, d| { let _ = tx.send((f, a, d.to_vec())); }).await; }), rx)
}

/// Device run loop as an app owner would wrap it: attached apps first, the owner's callback otherwise.
fn run_shared(n: Arc<Node>, local: Arc<Local>) -> (JoinHandle<()>, Rx) {
    let (tx, rx) = mpsc::unbounded_channel();
    (tokio::spawn(async move { let _ = n.run(move |f, a, d| if !local.deliver(f, a, d) { let _ = tx.send((f, a, d.to_vec())); }).await; }), rx)
}

async fn until(f: impl Fn() -> bool) {
    timeout(Duration::from_secs(15), async { while !f() { sleep(Duration::from_millis(50)).await } }).await.expect("condition");
}

async fn recv(rx: &mut Rx) -> (EndpointId, App, Vec<u8>) { timeout(Duration::from_secs(10), rx.recv()).await.expect("push").unwrap() }

#[tokio::test(flavor = "multi_thread")]
async fn mesh() {
    let _ = tracing_subscriber::fmt().with_env_filter("irpush=debug").with_test_writer().try_init();
    let (_relay, r) = relay().await;
    let (d1, d2, d3) = (dir(), dir(), dir());
    let (k1, k2, k3) = (random32(), random32(), random32());

    let h1 = Arc::new(Node::create(d1.join("s"), k1, vec![r.clone()]).unwrap());
    assert!(Node::create(d1.join("s"), k1, vec![]).is_err(), "never overwrite an identity");
    let dev_ticket = h1.ticket(Role::Device).unwrap();
    let host_ticket = h1.ticket(Role::Host).unwrap();

    // The device starts first; the host comes online later: pairing must retry.
    let dev = Arc::new(Node::join(d3.join("s"), k3, &dev_ticket, vec![]).unwrap());
    let (dt, mut drx) = run(dev.clone());
    sleep(Duration::from_secs(1)).await;
    let (_t1, _) = run(h1.clone());
    until(|| dev.peers().len() == 1 && h1.peers().len() == 1).await;
    let w = dev.relay_watch();
    assert_eq!(w.borrow().as_deref(), Some(r.url.as_str()), "status reports the relay in use");
    assert!(!irpush::is_n0(&r.url));

    // A second host joins and is introduced to the device.
    let h2 = Arc::new(Node::join(d2.join("s"), k2, &host_ticket, vec![]).unwrap());
    let (_t2, _) = run(h2.clone());
    until(|| h2.peers().len() == 2 && dev.peers().len() == 2).await;
    assert!(h1.ticket(Role::Device).is_ok() && dev.ticket(Role::Device).is_err(), "only hosts issue tickets");

    let (a, id) = (app("org.example.chat"), dev.id());
    h1.push(id, &a, b"from h1").unwrap();
    assert_eq!(recv(&mut drx).await, (h1.id(), a, b"from h1".to_vec()));
    h2.push(id, &a, b"from h2").unwrap();
    assert_eq!(recv(&mut drx).await.2, b"from h2");

    // No network: the device parks (no reconnect attempts); pushes queue on the host meanwhile.
    dev.network(irpush::OFFLINE);
    until(|| dev.relay_watch().borrow().is_none()).await;
    h1.push(id, &a, b"while parked").unwrap();
    assert!(timeout(Duration::from_secs(2), drx.recv()).await.is_err(), "parked: nothing arrives");
    dev.network(1);
    assert_eq!(recv(&mut drx).await.2, b"while parked");

    // Offline: queued on the host, delivered when the device comes back.
    dt.abort();
    drop(dev);
    sleep(Duration::from_millis(500)).await;
    h1.push(id, &a, b"while offline").unwrap();
    let dev = Arc::new(Node::open(d3.join("s"), k3, vec![]).unwrap());
    let (_dt, mut drx) = run(dev.clone());
    assert_eq!(recv(&mut drx).await.2, b"while offline");

    // Revoked from h2: h1 learns it too and refuses to push.
    h2.revoke(id).unwrap();
    until(|| !h1.peers().iter().any(|p| p.0 == id)).await;
    assert!(h1.push(id, &a, b"x").is_err());
    assert!(Node::open(d1.join("s"), random32(), vec![]).is_err(), "wrong state key");
    for d in [d1, d2, d3] { let _ = std::fs::remove_dir_all(d); }
}

/// One node per phone: a second app attaches over the local socket and gets its pushes; pushes for
/// apps nobody attached fall through to the owner; the owner refuses an attach it does not allow.
#[tokio::test(flavor = "multi_thread")]
async fn shared_node() {
    let (_relay, r) = relay().await;
    let (dh, dd) = (dir(), dir());
    let h = Arc::new(Node::create(dh.join("s"), random32(), vec![r.clone()]).unwrap());
    let dev = Arc::new(Node::join(dd.join("s"), random32(), &h.ticket(Role::Device).unwrap(), vec![]).unwrap());
    let (_th, _) = run(h.clone());
    let local = Arc::new(Local::default());
    let (_td, mut owner_rx) = run_shared(dev.clone(), local.clone());
    until(|| dev.peers().len() == 1 && h.peers().len() == 1).await;

    let sock = if cfg!(any(target_os = "linux", target_os = "android")) { format!("@irpush-test-{}", hex::encode(&random32()[..4])) } else { dd.join("sock").to_string_lossy().into_owned() };
    let (a, b, denied) = (app("org.example.a"), app("org.example.b"), app("org.example.denied"));
    let allowed = move |_uid: Option<u32>, apps: &std::collections::HashSet<App>| !apps.contains(&denied);
    tokio::spawn(local::serve(dev.clone(), local.clone(), local::bind(&sock).unwrap(), allowed, |_, _, _| anyhow::bail!("no commands")));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (atx, mut arx) = mpsc::unbounded_channel();
    let (ltx, mut lrx) = mpsc::unbounded_channel();
    let id = local::attach(&sock, &[a], move |f, ap, d| { let _ = atx.send((f, ap, d.to_vec())); }, move || { let _ = ltx.send(()); }).unwrap();
    assert_eq!(id, dev.id(), "attached apps learn the shared device id");
    assert!(local::attach(&sock, &[denied], |_, _, _| {}, || {}).is_err(), "owner's allow() is enforced");
    assert!(local::bind(&sock).is_err(), "the socket is the election: a second owner cannot bind");

    h.push(id, &a, b"for app a").unwrap();
    assert_eq!(recv(&mut arx).await, (h.id(), a, b"for app a".to_vec()));
    h.push(id, &b, b"for app b").unwrap();
    assert_eq!(recv(&mut owner_rx).await, (h.id(), b, b"for app b".to_vec()), "unattached apps reach the owner's callback");
    assert!(timeout(Duration::from_millis(300), arx.recv()).await.is_err(), "app a never sees app b's push");

    drop(_td);
    for d in [dh, dd] { let _ = std::fs::remove_dir_all(d); }
    let _ = lrx.try_recv();
}
