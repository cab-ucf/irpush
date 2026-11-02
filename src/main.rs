//! irpush: host daemon and CLI.
const USAGE: &str = "\
usage:
  irpush DIR create [RELAYS]       found a mesh as its first host; RELAYS = \"https://r.example#hextoken,...\"
  irpush DIR join TICKET [RELAYS]  join a mesh (RELAYS: an app's default relays, devices only)
  irpush DIR run [RELAYS]          run; prints \"sender app data\" (hex) per push; serves DIR/sock
  irpush DIR ticket [host]         one-time ticket, valid 10 min (treat as a secret)
  irpush DIR push DEVICE APP       send stdin (<= 1536 B) to APP (e.g. org.example.chat) on DEVICE
  irpush DIR relays RELAYS         set the mesh relays (also relay-token rotation)
  irpush DIR id | peers | revoke ID
  irpush DIR apns KEYID TEAMID < AuthKey.p8      host: send iOS pushes straight to APNs
  irpush DIR route apns|sandbox TOPIC TOKENHEX   device: APNs route (iOS apps do this via the C ABI)
  irpush DIR nse < B64             decrypt an APNs payload's \"f\", as the iOS extension does
  irpush token                     random relay token, for relay.toml access.shared_token
State key (KEK): $CREDENTIALS_DIRECTORY/irpush.kek (systemd-creds, TPM-bound), else DIR/kek.
Logs: stderr, RUST_LOG (default irpush=info).";

use anyhow::{Context, Result, bail};
use irpush::{BODY, Node, Relay, Role, Svc, app, random32, write_private};
use std::{fs, io::{Read, Write}, os::unix::{fs::{MetadataExt, PermissionsExt}, net::UnixStream}, path::Path, sync::Arc};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::UnixListener};

fn kek(dir: &Path) -> Result<[u8; 32]> {
    let p = std::env::var_os("CREDENTIALS_DIRECTORY").map(|d| Path::new(&d).join("irpush.kek")).filter(|p| p.exists()).unwrap_or(dir.join("kek"));
    if !p.exists() { write_private(&p, &random32())?; }
    fs::read(&p)?.try_into().map_err(|_| anyhow::anyhow!("{}: must be 32 bytes", p.display()))
}

/// Client side of DIR/sock: one command line (+ stdin body for push/apns), prints the answer.
fn client(dir: &Path, cmd: &str, args: &[&str]) -> Result<()> {
    let mut s = UnixStream::connect(dir.join("sock")).context("no running node (irpush DIR run)")?;
    s.write_all(format!("{cmd} {}\n", args.join(" ")).as_bytes())?;
    if cmd == "push" || cmd == "apns" { std::io::copy(&mut std::io::stdin().take(BODY as u64 + 1), &mut s)?; }
    s.shutdown(std::net::Shutdown::Write)?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    if let Some(e) = out.strip_prefix("error: ") { bail!("{}", e.trim()) }
    print!("{out}");
    Ok(())
}

fn command(n: &Node, line: &str, body: Vec<u8>) -> Result<String> {
    let w: Vec<&str> = line.split_whitespace().collect();
    Ok(match w.as_slice() {
        ["push", dev, a] => { n.push(dev.parse()?, &app(a), &body)?; String::new() }
        ["ticket"] => n.ticket(Role::Device)? + "\n",
        ["ticket", "host"] => n.ticket(Role::Host)? + "\n",
        ["revoke", id] => { n.revoke(id.parse()?)?; String::new() }
        ["relays", l] => { n.set_relays(Relay::list(l)?)?; String::new() }
        ["apns", kid, team] => { n.set_apns_key(kid, team, std::str::from_utf8(&body)?)?; String::new() }
        ["route", svc, topic, tok] => { n.set_route(if *svc == "sandbox" { Svc::ApnsSandbox } else { Svc::Apns }, topic, &hex::decode(tok)?)?; String::new() }
        ["id"] => format!("{}\n", n.id()),
        ["peers"] => n.peers().iter().map(|(i, r)| format!("{i} {r:?}\n")).collect(),
        _ => bail!("unknown command"),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "irpush=info".into())).init();
    let a: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let (dir, cmd, rest) = match a.as_slice() {
        ["token"] => { println!("{}", hex::encode(random32())); return Ok(()) }
        [d, c, r @ ..] => (Path::new(d), *c, r),
        _ => { eprintln!("{USAGE}"); std::process::exit(2) }
    };
    let relays = |r: &[&str]| Relay::list(r.first().copied().unwrap_or(""));
    let state = dir.join("state");
    let node = match (cmd, rest) {
        ("create" | "join" | "run", r) if r.len() <= 2 => {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            let lock = fs::File::create(dir.join("lock"))?;
            lock.try_lock().map_err(|_| anyhow::anyhow!("{} is in use by another irpush", dir.display()))?;
            let n = match (cmd, r) {
                ("create", r) if r.len() <= 1 => Node::create(&state, kek(dir)?, relays(r)?)?,
                ("join", [t, r @ ..]) if r.len() <= 1 => Node::join(&state, kek(dir)?, t, relays(r)?)?,
                ("run", r) if r.len() <= 1 => Node::open(&state, kek(dir)?, relays(r)?)?,
                _ => { eprintln!("{USAGE}"); std::process::exit(2) }
            };
            (n, lock)
        }
        ("nse", []) => {
            let mut b = String::new();
            std::io::stdin().read_to_string(&mut b)?;
            match irpush::open_notification(&state, &kek(dir)?, b.trim())? {
                Some((from, app, d)) => println!("{from} {} {}", hex::encode(app), hex::encode(d)),
                None => println!("none"),
            }
            return Ok(());
        }
        _ => return client(dir, cmd, rest),
    };
    let (node, _lock) = (Arc::new(node.0), node.1);
    tracing::info!(id = %node.id(), role = ?node.role(), "started");
    let sock = dir.join("sock");
    let _ = fs::remove_file(&sock); // we hold DIR/lock: any socket here is stale
    let (l, uid) = (UnixListener::bind(&sock)?, dir.metadata()?.uid()); // 0700 dir + peer uid check
    let n = node.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            if s.peer_cred().map(|c| c.uid()).ok() != Some(uid) { continue }
            let n = n.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(&mut s);
                let (mut line, mut body) = (String::new(), vec![]);
                if r.read_line(&mut line).await.is_err() || r.take(BODY as u64 + 1).read_to_end(&mut body).await.is_err() { return }
                let out = command(&n, &line, body).unwrap_or_else(|e| format!("error: {e:#}\n"));
                let _ = s.write_all(out.as_bytes()).await;
            });
        }
    });
    node.run(|from, app, d| println!("{from} {} {}", hex::encode(app), hex::encode(d))).await
}
