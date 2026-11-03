{
  description = "irpush: post-quantum E2EE push for iroh apps, plus an optional relay VPS";

  inputs = {
    # Pinned by flake.lock; `make bump` moves both.
    nixpkgs.url = "https://channels.nixos.org/nixos-26.05/nixexprs.tar.xz";
    disko = { url = "git+https://github.com/nix-community/disko"; inputs.nixpkgs.follows = "nixpkgs"; };
  };

  outputs = { self, nixpkgs, disko }:
    let
      lib = nixpkgs.lib;
      cfg = import ./deploy/config.nix;
      each = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      fs = lib.fileset;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      relay = pkgs: pname: patches: features: pkgs.rustPlatform.buildRustPackage {
        inherit pname patches;
        version = "1.4.1";
        src = pkgs.fetchCrate { pname = "iroh-relay"; version = "1.4.1"; hash = "sha256-FOJJwZnmXHSM8nSvWIJoD+EMPASJfFIti3/X8E+cRxw="; };
        cargoLock.lockFile = ./deploy/iroh-relay.Cargo.lock;
        buildFeatures = [ "server" ] ++ features;
        cargoBuildFlags = [ "--bin" "iroh-relay" ];
        doCheck = false;
      };
    in {
      packages = each (system: let pkgs = pkgsFor system; in {
        default = self.packages.${system}.irpush;
        irpush = pkgs.rustPlatform.buildRustPackage {
          pname = "irpush";
          version = "0.1.6";
          src = fs.toSource { root = ./.; fileset = fs.unions [ ./Cargo.toml ./Cargo.lock ./src ]; };
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        };
        iroh-relay = relay pkgs "iroh-relay" [ ] [ ];                                # stock: iroh data relay
        # server ping after 130 min of client silence (clients drive heartbeats); TLS by aws-lc-rs with
        # X25519MLKEM768 first, so the relay hop is post-quantum (stock iroh-relay: ring, X25519 only)
        irpush-relay = relay pkgs "irpush-relay" [ ./deploy/relay-ping.patch ./deploy/relay-pq.patch ] [ "tls-aws-lc-rs" ];
      });

      nixosModules.relays = import ./deploy/relays.nix self;

      nixosConfigurations.relay = lib.nixosSystem {
        inherit (cfg) system;
        modules = [ disko.nixosModules.disko self.nixosModules.relays ./deploy/host.nix ];
      };
    };
}
