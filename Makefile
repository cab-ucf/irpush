# Relay VPS (optional). Edit deploy/config.nix, point both DNS names at the VPS, then:
#   make deploy HOST=1.2.3.4   # first time: installs NixOS over a fresh Ubuntu/Debian VPS (wipes it)
#   make update HOST=...       # apply config changes
#   make key HOST=...          # a new key that lifts the relay's rate limit (`make keys`: all of them)
HOST ?=
SSH := ssh root@$(HOST)
IOS := aarch64-apple-ios aarch64-apple-ios-sim

build:
	cargo build --release

# A host with its own relay (`irpush DIR run --serve PORT`) that pings its
# members hours apart: built against iroh-relay with the ping interval patch.
RELAY := target/iroh-relay-1.4.1
REGISTRY := $(or $(CARGO_HOME),$(HOME)/.cargo)/registry/src
desktop:
	cargo fetch
	test -d $(RELAY) || { mkdir -p target && \
	  cp -r $(firstword $(wildcard $(REGISTRY)/*/iroh-relay-1.4.1)) $(RELAY) && \
	  patch -s -d $(RELAY) -p1 < deploy/iroh-relay-ping-interval.patch; }
	cp Cargo.lock target/Cargo.lock.orig
	cargo build --release --features relay-ping \
	  --config 'patch.crates-io.iroh-relay.path="$(RELAY)"'; \
	  s=$$?; cp target/Cargo.lock.orig Cargo.lock; exit $$s

deploy:
	nix run github:nix-community/nixos-anywhere -- --build-on remote --flake .#relay root@$(HOST)

update:
	nix run nixpkgs#nixos-rebuild -- switch --flake .#relay --target-host root@$(HOST) --build-host root@$(HOST)

key:
	$(SSH) 'umask 077; d=/var/lib/private/irpush-relay; openssl rand -hex 32 >> $$d/keys && chown --reference=$$d $$d/keys && tail -1 $$d/keys'

keys:
	$(SSH) cat /var/lib/private/irpush-relay/keys

bump:
	nix flake update

ios:
	rustup target add $(IOS)
	for t in $(IOS); do cargo build --release --lib --features ffi --target $$t; done
	rm -rf Irpush.xcframework
	xcodebuild -create-xcframework \
	  -library target/aarch64-apple-ios/release/libirpush.a -headers ios/include \
	  -library target/aarch64-apple-ios-sim/release/libirpush.a -headers ios/include \
	  -output Irpush.xcframework

.PHONY: build desktop deploy update key keys bump ios
