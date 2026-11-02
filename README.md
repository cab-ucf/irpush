# irpush

Push notifications for iroh apps, end-to-end encrypted with post-quantum keys. One socket per phone,
shared by every irpush app on it. Your always-on desktops are the servers. Works with zero
infrastructure; one optional VPS improves Android battery and privacy.

## Principles
1. **Plug-and-play, no required infrastructure.** Ultra-secure, highly private push with zero cloud setup.
   Your desktops are the servers; one irpush connection per phone serves all your iroh apps.
2. **Optional, tiny relay.** One small self-hosted relay improves connectivity consistency; it is never
   required. Personal desktops are sufficient for personal apps.
3. **Modern, simple post-quantum crypto.** X-Wing (ML-KEM-768 + X25519) for every frame, nothing exotic.
   End-to-end only: nothing is ever decrypted off an endpoint. Minimal metadata, constant-size frames.
   One key per purpose.
4. **Rust as much as possible.** Platform glue (Swift, Kotlin) stays a thin shell over the Rust core.
5. **Battery first, at every step.** One shared TCP socket per phone with long, learned keepalives;
   no polling; work rides on wakeups that already happen. Target: < 1 % battery per day for all iroh
   apps on a phone combined.
6. **iroh over cloud servers.** iroh makes desktops reachable across the WAN, so no cloud servers.
7. **Own infrastructure first.** Prefer the user's, then the developer's own relays; free services
   (n0's public relays) only as the last resort, and apps are told when that happens.
8. **No big-company infrastructure.** No Google (no FCM), no corporate clouds. The one exception is
   forced by the platform: iOS allows background delivery only through Apple's APNs, which carries
   sealed, constant-size frames posted directly by your own hosts.
9. **FOSS, minimal, Unix.** Small composable tools (one CLI, a Unix socket, files, systemd, Nix),
   few well-trusted dependencies, no telemetry, no proprietary blobs, less code over more features.

## How it works
- **Hosts** (desktops): queue pushes for 24 h, issue pairing tickets, introduce members, revoke,
  post to APNs directly for iOS. They listen on every relay a member might use.
- **Devices** (phones): one TLS/TCP connection to the first working relay, preferring the mesh's
  relays, then the app's defaults, then n0's public relay as the always-available last resort.
  `Node::relay_watch` / `irp_status` / `Irpush.relayChanged` report when n0 is in use, so apps can
  show a notice. Heartbeats are learned per network by testing the *inbound* path (a host
  echoes after the candidate silence), so NATs and VPNs that silently drop inbound traffic
  (e.g. WireGuard without PersistentKeepalive) are detected rather than assumed alive.
- **One node per phone**: the first irpush app runs the node and serves it (`DIR/sock` on desktops,
  Binder on Android, see below); every later app `attach`es its app ids and receives their pushes. The kernel's bind is the election:
  when the owner dies, the next app whose connect fails binds and takes over. Pushes for apps that
  are not attached reach the owner's platform callback, which wakes them. The owner authenticates
  attaching processes by uid (Android: uid -> package names -> `irp_app(package)`). The owner process
  decrypts every frame, so the apps of one phone trust each other as they trust the OS.
- **Devices meet hosts only**: hosts are introduced to everyone, devices never to each other, so one
  host can serve many people's phones without telling one of another.
- **iOS**: Apple forbids sockets across apps, so apps of one team share the identity through the App
  Group (one device id, one APNs route per app, sent as `Route` frames) and each foreground app holds
  the socket while it runs. In the background the socket is closed; hosts post the same sealed frame
  to APNs and the app's Notification Service Extension decrypts it *on the phone*.
- **Frames**: 2715 B, always. X-Wing (ML-KEM-768 + X25519) per frame to the recipient's key, plus a
  pairwise PSK, bound to sender, recipient and direction; ChaCha20-Poly1305. Timestamped (25 h
  window) and de-duplicated by id. State at rest: one XChaCha20-Poly1305 file under a platform key.
- **Relay hop**: TLS 1.3 with X25519MLKEM768 key exchange (rustls, aws-lc-rs provider), so the
  metadata the relay hop carries (endpoint ids, tokens) is not harvest-now-decrypt-later exposed either.

## Threat model
| Party | Sees | Cannot |
|---|---|---|
| Relay operator (yours, the app developer's, n0 fallback) | endpoint ids, IPs, timing, direction | read, forge, replay into acceptance, learn app/kind/size |
| Apple (iOS) | bundle id, device token, timing, fixed size | read, learn the sending host |
| Network / VPN | as relay operator, minus ids (TLS) | as relay operator |
| A paired device | its own traffic, its hosts | learn other devices, add members, revoke, change relays, impersonate hosts |
| Holder of an unused ticket (10 min) | | pair as the role the ticket grants; treat tickets as secrets |
| A host | everything of its mesh | (hosts are trusted infrastructure by design) |
| Another irpush app on the phone | if it is the owner: every app's pushes on that phone | attach for an app id its uid's packages do not hash to |

Forward secrecy: weekly X-Wing key rotation; a stolen device key exposes at most one epoch of
frames *to that device*, and only together with the pairwise PSK. Endpoint ids are long-lived, so a
relay can link a device's sessions over time. Device-suggested relays must be `https://<domain>`
(no IPs), so a member cannot point hosts at their LAN.

## Use
    irpush ~/.irpush create                                  # first host (zero infrastructure)
    irpush ~/.irpush create "https://irpush.you.example#TOKEN"   # ... or preferring your relay
    irpush ~/.irpush run &                                   # as a service (systemd)
    irpush ~/.irpush ticket host | qrencode -t ansiutf8      # add a host
    irpush ~/.irpush ticket                                  # add a device (in-band or QR)
    irpush NEWDIR join TICKET                                # on the new node, then `run`
    echo hi | irpush ~/.irpush push DEVICE_ID org.example.chat   # <= 1536 B
    irpush ~/.irpush id | peers | revoke ID
    irpush ~/.irpush attach org.example.chat org.example.mail   # stream these apps' pushes (any program)
    irpush ~/.irpush relays "https://a.example#TOKEN,https://b.example"   # later changes
    irpush ~/.irpush relays "https://a.example#TOKEN,!n0"   # never fall back to n0 (whole mesh)

Library: `Node::{create, join, open}`, `run(callback)`, `push`, `ticket`, `revoke`, `set_relays`,
`set_route` / `set_apns_key` (iOS), `network` / `kick` / `pause` (platform hooks); `local::{bind,
serve, attach}` and `Local::deliver` for the shared node. C ABI: `src/ffi.rs` (`irp_serve` / `irp_attach`).

## Android (Kotlin shell, to be written against the C ABI)
Since Android 9 every app has its own SELinux categories: no app can reach another's Unix socket,
abstract ones included. Across apps the broker is therefore Binder. The owner runs
`irp_open`/`irp_join` in a `remoteMessaging` foreground service (`dataSync` stops after 6 h a day
from Android 15) that other apps bind to (`org.irpush.ATTACH`, found with `queryIntentServices`).
It authenticates them as `auth` does here: `Binder.getCallingUid()` -> `getPackagesForUid` ->
`irp_app(pkg)`. Each `cb` push goes to the bound app, or, when none is bound, to an explicit
broadcast that wakes it. `irp_serve` / `irp_attach` stay for the processes of one app and for desktops.
Hooks:
- `irp_network(id)` from `ConnectivityManager`, with `id` a hash of the interface name and DNS
  servers (`wlan0` alone is every Wi-Fi), and `UINT64_MAX` when the network is lost.
- `irp_kick()` from `AlarmManager.setAndAllowWhileIdle` (no exact-alarm permission needed), under a
  10 s wake lock; it returns the seconds until the next alarm.

If the owning app is uninstalled, the state goes with it and the phone re-pairs with one ticket.

## iOS
Host, once: `irpush ~/.irpush apns KEYID TEAMID < AuthKey_KEYID.p8` (one key covers your apps).
`make ios` (macOS + Xcode) builds `Irpush.xcframework`; add this repo as a Swift package.
App and extension: App Groups + Keychain Sharing (same group), Push Notifications on the app.
Info.plist (both): `IrpushGroup = group.your.app`; app, optional: `IrpushRelays = https://irpush.you.example#TOKEN`.

    Irpush.start(ticket: firstRunTicket) { from, app, data in DispatchQueue.main.async { /* deliver */ } }
    func application(_: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken t: Data) { Irpush.register(apnsToken: t) }
    class NotificationService: IrpushNotificationService {       // extension target
        override func render(app: Data, data: Data) -> (title: String, body: String) { ("Chat", String(decoding: data, as: UTF8.self)) }
    }

## Your own relays (optional VPS)
`iroh.<you>` (stock iroh relay) and `irpush.<you>` (1 h server ping so clients drive heartbeats;
token-gated; rate-limited) share :443 by SNI on one NixOS box. The token embedded in an app is
not a secret: it keeps strangers off the relay, and rate limits bound what a holder can use.

1. A VPS (DigitalOcean 2 GB for the install, or Hetzner) with a dedicated SSH key; both DNS names -> its IP.
2. Edit `deploy/config.nix`. `make deploy HOST=ip` (nixos-anywhere, built on the VPS). Later `make update`.
3. `make token HOST=ip` -> `https://irpush.<you>#TOKEN` in your app, or `irpush DIR relays ...` for a mesh.

Rotate after a revoke: `make token-add`, `irpush DIR relays "https://irpush.<you>#NEW"`, then after a
grace period `make token-drop`. The VPS clamps TCP MSS to 1120 (fits WireGuard on a 1280-byte path),
keeps logs at warn level for 7 days, and can upgrade itself nightly (`autoUpgrade`).

## Battery
One socket per phone; heartbeats up to 28 min (learned per network, persisted); any inbound traffic
counts as a heartbeat; relay preference re-checked only on wakeups that happen anyway; failing relays
backed off (5 min .. 6 h); no network (`network(OFFLINE)`) parks the device with no retries at all.
Stock iroh relays (n0's, or yours unpatched) ping every client every 15 s, which keeps a phone's
radio awake: the battery target needs the patched relay below. `!n0` keeps a mesh off n0's.

Chatter: frames go only where they are needed. Devices meet hosts only, so key rotations and
introductions never fan out to phones that are asleep.

Replay: pushes are de-duplicated by a delivered-id log shared with the iOS extension (locked), every
other frame kind by an in-memory id set over the 25 h freshness window. Long-lived secrets are wiped
from memory when dropped.

## Tests
`cargo test`: frame crypto (binding, tamper, freshness), state round trip, relay parsing, APNs JWT and
per-app routes, an end-to-end mesh over an in-process relay (late-host pairing, introductions, two
hosts, offline queue, parking with no network, revocation, identity and key guards), the shared node
(attach, device id, fall-through to the owner, refused attach, single owner), and the `!n0` opt-out.
CI also runs clippy with `-D warnings`, `cargo audit`, and builds the iOS xcframework and Swift package.

## Limits
Host queues live in memory (a host restart drops unacknowledged pushes, and replay protection for
non-push frames restarts with them). The protocol has not been formally verified or externally
audited; `x-wing` (draft-06) and `ml-kem` are unaudited crates, acceptable only because the
construction is hybrid with X25519 and a pairwise PSK. CI compiles the Swift package; no device run
is automated. The Android shell is specified above, not yet written. On Android the node's state
belongs to the app that first became owner; uninstalling it means one re-pair.

## Prior art
UnifiedPush already gives Android one connection that all apps share, and FCM learns heartbeats
adaptively; Web Push (RFC 8291) seals payloads end to end. irpush differs in three ways: it needs no
push server beyond your own iroh hosts, its heartbeat is learned by testing the inbound path, and every
frame is post-quantum and constant-size. Its Android shell could also act as a UnifiedPush
distributor for apps that can POST to a host.

License: GPL-3.0-or-later.
