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

## One socket per device
- [ ] Desktops: irch's iroh endpoint and irpush's device on one relay
      socket (one endpoint shared by every iroh app, as on phones)
- [ ] Measure: packets an idle device sends a day, per relay

## Hosts that form themselves
- [ ] An app's hosts of one owner join one mesh with no manual ticket
- [ ] A device registers with every host of its mesh; any one rings it
