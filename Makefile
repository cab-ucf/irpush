# Relay VPS (optional). Edit deploy/config.nix, point both DNS names at the VPS, then:
#   make deploy HOST=1.2.3.4   # first time: installs NixOS over a fresh Ubuntu/Debian VPS (wipes it)
#   make update HOST=...       # apply config changes
HOST ?=
SSH := ssh root@$(HOST)
IOS := aarch64-apple-ios aarch64-apple-ios-sim

build:
	cargo build --release

deploy:
	nix run github:nix-community/nixos-anywhere -- --build-on remote --flake .#relay root@$(HOST)

update:
	nix run nixpkgs#nixos-rebuild -- switch --flake .#relay --target-host root@$(HOST) --build-host root@$(HOST)

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

.PHONY: build deploy update bump ios
