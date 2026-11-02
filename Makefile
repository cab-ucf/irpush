# Relay VPS (optional). Edit deploy/config.nix, point both DNS names at the VPS, then:
#   make deploy HOST=1.2.3.4   # first time: installs NixOS over a fresh Ubuntu/Debian VPS (wipes it)
#   make update HOST=...       # apply config changes
#   make token  HOST=...       # current irpush relay token(s), one per line
#   make token-add / token-drop HOST=...   # rotation: add new, roll out, later drop the old ones
HOST ?=
SSH := ssh root@$(HOST)
IOS := aarch64-apple-ios aarch64-apple-ios-sim
T := /var/lib/irpush-relay/tokens

build:
	cargo build --release

deploy:
	nix run github:nix-community/nixos-anywhere -- --build-on remote --flake .#relay root@$(HOST)

update:
	nix run nixpkgs#nixos-rebuild -- switch --flake .#relay --target-host root@$(HOST) --build-host root@$(HOST)

token:
	$(SSH) cat $(T)

token-add:
	$(SSH) 'openssl rand -hex 32 >> $(T) && systemctl restart irpush-relay && tail -1 $(T)'

bump:
	nix flake update

token-drop:
	$(SSH) 'tail -1 $(T) > $(T).new && mv $(T).new $(T) && systemctl restart irpush-relay && cat $(T)'

ios:
	rustup target add $(IOS)
	for t in $(IOS); do cargo build --release --lib --features ffi --target $$t; done
	rm -rf Irpush.xcframework
	xcodebuild -create-xcframework \
	  -library target/aarch64-apple-ios/release/libirpush.a -headers ios/include \
	  -library target/aarch64-apple-ios-sim/release/libirpush.a -headers ios/include \
	  -output Irpush.xcframework

.PHONY: build deploy update bump token token-add token-drop ios
