# TODO

irch's plan (the why): irch's PLAN.md.

## Relay: reachable by anyone
- [x] No token: anyone may connect, so every device homed here is
      reachable by everyone; limits, per-IP caps and idle timeouts bound abuse
- [x] Per-client rate fit for relayed calls (direct paths have no limit)
- [x] Keys lift it (`make key`): a lab's terabytes through its own relay
- [x] QUIC address discovery, so devices homed here find direct paths
- [ ] Deploy (`make update HOST=…`)
- [ ] One relay for everything: serve the stock name too, drop the second
- [ ] Deploy from the app: a VPS provider's API token in, a relay out
      (cloud-init, a signed static binary, an IP certificate or the
      provider's DNS); or a storage node with a public address serves one
- [x] A desktop as the relay (`run --serve PORT`): members only, its
      certificate pinned in its address, the port mapped by the router
- [ ] Its addresses for devices off every relay: published under the
      host's key (pkarr), so a moved home IP is found without a fallback
- [ ] Upstream the ping interval (deploy/iroh-relay-ping-interval.patch):
      then n0's relays could leave silent clients alone too

## One socket per device
- [x] Events: any two nodes on one relay, one datagram each (`Node::event`)
- [x] Android: apps in the owner's process use its node (`shared`, `tap`)
- [ ] An iroh custom transport over the device's irpush socket
      (`unstable-custom-transports`): an app's endpoint keeps no relay of
      its own (then, measured, it sends nothing at rest), is reached
      through the socket already up, and answers a ring one round trip
      later; desktops too (irch's endpoint and irpush's device as one)
- [x] Measure an idle iroh endpoint: ~69k packets a day (README, Battery)
- [ ] Measure an idle irpush device on a phone, per relay

## Upstream (iroh)
- [ ] Cache the first QAD report (iroh#4523): ~25 MB a day per idle
      endpoint, a QUIC handshake every 20-26 s
- [ ] One end of a connection keeps each path alive, and stops after
      idle, as iroh 0.35 did (noq#810)

## Hosts that form themselves
- [ ] An app's hosts of one owner join one mesh with no manual ticket
- [ ] A device registers with every host of its mesh; any one rings it
