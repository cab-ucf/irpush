#!/bin/sh
# Open the relay (no token; keys lift the rate limit): ./fix.sh VPS_IP
set -eu
h=${1:?usage: ./fix.sh VPS_IP}
cd "$(dirname "$0")"
mine=$(git diff --quiet || echo y)   # your deploy/config.nix, kept
[ -z "$mine" ] || git stash -q
git pull -q --ff-only origin main
[ -z "$mine" ] || git stash pop -q
make update HOST="$h"
d=$(sed -n 's/^ *irpushDomain = "\([^"]*\)".*/\1/p' deploy/config.nix)
ssh "root@$h" systemctl is-active irpush-relay
curl -fsS "https://$d/ping" >/dev/null && echo "https://$d is up, open to all"
