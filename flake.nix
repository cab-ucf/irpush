{
  description = "irpush: post-quantum E2EE push for iroh apps, plus an optional relay VPS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    disko = { url = "github:nix-community/disko"; inputs.nixpkgs.follows = "nixpkgs"; };
  };

  outputs = { self, nixpkgs, disko }:
    let
      lib = nixpkgs.lib;
      cfg = import ./deploy/config.nix;
      each = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      fs = lib.fileset;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      relay = pkgs: pname: patches: pkgs.rustPlatform.buildRustPackage {
        inherit pname patches;
        version = "1.4.1";
        src = pkgs.fetchCrate { pname = "iroh-relay"; version = "1.4.1"; hash = "sha256-FOJJwZnmXHSM8nSvWIJoD+EMPASJfFIti3/X8E+cRxw="; };
        cargoLock.lockFile = ./deploy/iroh-relay.Cargo.lock;
        buildFeatures = [ "server" ];
        cargoBuildFlags = [ "--bin" "iroh-relay" ];
        doCheck = false;
      };
    in {
      packages = each (system: let pkgs = pkgsFor system; in {
        default = self.packages.${system}.irpush;
        irpush = pkgs.rustPlatform.buildRustPackage {
          pname = "irpush";
          version = "0.1.0";
          src = fs.toSource { root = ./.; fileset = fs.unions [ ./Cargo.toml ./Cargo.lock ./src ]; };
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        };
        iroh-relay = relay pkgs "iroh-relay" [ ];                                # stock: iroh data relay
        irpush-relay = relay pkgs "irpush-relay" [ ./deploy/relay-ping.patch ];  # 3 h server ping: clients drive heartbeats
      });

      nixosModules.relays = import ./deploy/relays.nix self;

      nixosConfigurations.relay = lib.nixosSystem {
        inherit (cfg) system;
        modules = [ disko.nixosModules.disko self.nixosModules.relays ./deploy/host.nix ];
      };
    };
}
