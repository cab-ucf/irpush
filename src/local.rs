//! One node per phone (or desktop), shared by every irpush app on it over a Unix socket.
//!
//! The first app to bind the socket runs the node and serves it; every later app connects and
//! `attach`es its app ids, then receives their pushes over the socket. The kernel's bind is the
//! election: if the owner dies, the next app whose connect fails binds and becomes the owner.
//! Pushes for apps that are not attached fall through to the owner's platform callback (which can
//! wake the app). Peers are authenticated by uid: the desktop allows its own uid, Android glue
//! maps the uid to package names and checks them against the app ids.
//!
//! Protocol (UTF-8 lines, one request per connection, all binary fields hex):
//!   attach APP [APP...]   -> `id DEVICE` then `push FROM APP DATA` per push, until EOF
//!   anything else         -> the owner's command handler (the CLI's push/ticket/revoke/...), one reply
//! `@name` paths are Linux abstract sockets (reachable across Android app sandboxes).
use crate::{App, EndpointId, Node};
use anyhow::{Context, Result, bail};
use std::{collections::HashSet, io::{BufRead, BufReader, Write}, sync::{Arc, Mutex}};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt}, net::UnixListener, sync::mpsc};

/// Attached clients: which apps each one wants.
#[derive(Default)]
pub struct Local(Mutex<Vec<(HashSet<App>, mpsc::UnboundedSender<String>)>>);

impl Local {
    /// Hand a push to every attached client that wants `app`. False: nobody attached for it.
    pub fn deliver(&self, from: EndpointId, app: App, data: &[u8]) -> bool {
        let line = format!("push {} {} {}\n", hex::encode(from.as_bytes()), hex::encode(app), hex::encode(data));
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|c| !c.1.is_closed());
        l.iter().filter(|c| c.0.contains(&app)).filter(|c| c.1.send(line.clone()).is_ok()).count() > 0
    }
}

fn std_bind(p: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(name) = p.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        return std::os::unix::net::UnixListener::bind_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?);
    }
    let _ = std::fs::remove_file(p); // the caller holds the owner lock: any socket here is stale
    std::os::unix::net::UnixListener::bind(p)
}

fn std_connect(p: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(name) = p.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        return std::os::unix::net::UnixStream::connect_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?);
    }
    std::os::unix::net::UnixStream::connect(p)
}

/// Bind the broker socket. Fails if another process owns it (then `attach` instead).
pub fn bind(path: &str) -> Result<UnixListener> {
    let l = std_bind(path).with_context(|| format!("bind {path}"))?;
    l.set_nonblocking(true)?;
    Ok(UnixListener::from_std(l)?)
}

fn parse_apps(words: &[&str]) -> Result<HashSet<App>> {
    words.iter().map(|w| hex::decode(w)?.try_into().map_err(|_| anyhow::anyhow!("app: 16 bytes"))).collect()
}

/// Serve the socket forever. `allow(uid, apps)`: may this peer attach for these apps? With no apps:
/// may it run one-shot commands? `cmd(line, body)`: those commands (the CLI); `Err` for none.
pub async fn serve(node: Arc<Node>, local: Arc<Local>, l: UnixListener, allow: impl Fn(Option<u32>, &HashSet<App>) -> bool + Send + Sync + 'static,
    cmd: impl Fn(&Node, &str, Vec<u8>) -> Result<String> + Send + Sync + 'static) {
    let (allow, cmd) = (Arc::new(allow), Arc::new(cmd));
    while let Ok((mut s, _)) = l.accept().await {
        let uid = s.peer_cred().ok().map(|c| c.uid());
        let (node, local, allow, cmd) = (node.clone(), local.clone(), allow.clone(), cmd.clone());
        tokio::spawn(async move {
            let mut r = tokio::io::BufReader::new(&mut s);
            let mut line = String::new();
            if r.read_line(&mut line).await.is_err() { return }
            let w: Vec<&str> = line.split_whitespace().collect();
            if let ["attach", apps @ ..] = w.as_slice() {
                let Some(apps) = parse_apps(apps).ok().filter(|a| !a.is_empty()) else { let _ = s.write_all(b"error: attach APP...\n").await; return };
                if !allow(uid, &apps) { let _ = s.write_all(b"error: not allowed\n").await; return }
                let (tx, mut rx) = mpsc::unbounded_channel();
                local.0.lock().unwrap_or_else(|e| e.into_inner()).push((apps, tx));
                if s.write_all(format!("id {}\n", hex::encode(node.id().as_bytes())).as_bytes()).await.is_err() { return }
                while let Some(m) = rx.recv().await { if s.write_all(m.as_bytes()).await.is_err() { return } }
                return;
            }
            if !allow(uid, &HashSet::new()) { let _ = s.write_all(b"error: not allowed\n").await; return } // commands: owner's rule
            let mut body = vec![];
            if r.take(crate::BODY as u64 + 1).read_to_end(&mut body).await.is_err() { return }
            let out = cmd(&node, &line, body).unwrap_or_else(|e| format!("error: {e:#}\n"));
            let _ = s.write_all(out.as_bytes()).await;
        });
    }
}

/// Attach to a running owner for `apps`; `on` gets each push on a background thread, then
/// `lost` once when the owner goes away (reconnect or become the owner). Returns the device id.
pub fn attach(path: &str, apps: &[App], on: impl Fn(EndpointId, App, &[u8]) + Send + 'static, lost: impl FnOnce() + Send + 'static) -> Result<EndpointId> {
    let mut s = std_connect(path).with_context(|| format!("connect {path}"))?;
    let line = apps.iter().map(hex::encode).collect::<Vec<_>>().join(" ");
    s.write_all(format!("attach {line}\n").as_bytes())?;
    let mut r = BufReader::new(s);
    let mut l = String::new();
    r.read_line(&mut l)?;
    let id = match l.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["id", h] => EndpointId::from_bytes(&hex::decode(h)?.try_into().map_err(|_| anyhow::anyhow!("id"))?)?,
        _ => bail!("{}", l.trim()),
    };
    std::thread::spawn(move || {
        for l in r.lines().map_while(Result::ok) {
            if let ["push", f, a, d] = l.split_whitespace().collect::<Vec<_>>().as_slice()
                && let (Ok(f), Ok(a), Ok(d)) = (hex::decode(f), hex::decode(a), hex::decode(d))
                && let (Ok(f), Ok(a)) = (EndpointId::from_bytes(&f.try_into().unwrap_or([0; 32])), <App>::try_from(a))
            { on(f, a, &d) }
        }
        lost();
    });
    Ok(id)
}

/// One-shot command to a running owner (the CLI client side).
pub fn command(path: &str, line: &str, body: &[u8]) -> Result<String> {
    let mut s = std_connect(path).context("no running node (irpush DIR run)")?;
    s.write_all(format!("{line}\n").as_bytes())?;
    s.write_all(body)?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut out = String::new();
    std::io::Read::read_to_string(&mut s, &mut out)?;
    if let Some(e) = out.strip_prefix("error: ") { bail!("{}", e.trim()) }
    Ok(out)
}

