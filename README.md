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
- **iOS**: in the background the app's socket is closed; hosts post the same sealed frame to APNs and
  the app's Notification Service Extension decrypts it *on the phone*.
- **Frames**: 2715 B, always. X-Wing (ML-KEM-768 + X25519) per frame to the recipient's key, plus a
  pairwise PSK, bound to sender, recipient and direction; ChaCha20-Poly1305. Timestamped (25 h
  window) and de-duplicated by id. State at rest: one XChaCha20-Poly1305 file under a platform key.

## Threat model
| Party | Sees | Cannot |
|---|---|---|
| Relay operator (yours, the app developer's, n0 fallback) | endpoint ids, IPs, timing, direction | read, forge, replay into acceptance, learn app/kind/size |
| Apple (iOS) | bundle id, device token, timing, fixed size | read, learn the sending host |
| Network / VPN | as relay operator, minus ids (TLS) | as relay operator |
| A paired device | its own traffic | add members, revoke, change relays, impersonate hosts |
| Holder of an unused ticket (10 min) | | pair as the role the ticket grants; treat tickets as secrets |
| A host | everything of its mesh | (hosts are trusted infrastructure by design) |

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
    irpush ~/.irpush relays "https://a.example#TOKEN,https://b.example"   # later changes

Library: `Node::{create, join, open}`, `run(callback)`, `push`, `ticket`, `revoke`, `set_relays`,
`set_route` / `set_apns_key` (iOS), `network` / `kick` / `pause` (platform hooks). C ABI: `src/ffi.rs`.

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
backed off (5 min .. 6 h). On n0 (zero infrastructure) its 15 s server pings cost Android battery.

## Tests
`cargo test`: frame crypto (binding, tamper, freshness), state round trip, relay parsing, APNs JWT,
and an end-to-end mesh over an in-process relay (late-host pairing, introductions, two hosts,
offline queue, revocation, identity and key guards).

## Limits
Host queues live in memory (a host restart drops unacknowledged pushes). The protocol has not been
formally verified or externally audited. The Swift and Xcode build have not been compiled here.
