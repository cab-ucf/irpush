# TODO

irch's plan (the why): irch's PLAN.md.

## Relay: reachable by anyone
- [x] Open by default: the token is an option (`requireToken`), abuse
      bounded by rate limits, per-IP connection caps and idle timeouts
- [x] Per-client rate limit fit for relayed calls, not only pushes
- [ ] Deploy (`make update HOST=…`), then irch homes on it everywhere
- [ ] Optional "home token": anyone may send to devices homed here, only
      holders may home (a patch to iroh-relay's send path)

## One socket per device
- [ ] Desktops: irch's iroh endpoint and irpush's device on one relay
      socket (one endpoint shared by every iroh app, as on phones)
- [ ] Measure: packets an idle device sends a day, per relay

## Hosts that form themselves
- [ ] An app's hosts of one owner join one mesh with no manual ticket
- [ ] A device registers with every host of its mesh; any one rings it
