{ lib, modulesPath, pkgs, ... }:
let c = import ./config.nix; in {
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") (import ./disk.nix { inherit (c) disk; }) ];

  boot.loader.grub = { enable = true; efiSupport = true; efiInstallAsRemovable = true; }; # boots BIOS or UEFI
  networking = { hostName = "relay"; useDHCP = true; };                                 # DO + Hetzner: IPv4 DHCP
  zramSwap.enable = true;

  services.openssh = {
    enable = true;
    settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; PermitRootLogin = "prohibit-password"; };
  };
  users.users.root.openssh.authorizedKeys.keys = c.sshKeys;

  services.irpushRelays = { enable = true; inherit (c) irohDomain irpushDomain email; };

  environment.systemPackages = [ pkgs.openssl ];
  services.journald.extraConfig = "MaxRetentionSec=7day"; # privacy: short log retention
  system.autoUpgrade = lib.mkIf (c.autoUpgrade != null) { enable = true; flake = c.autoUpgrade; allowReboot = true; dates = "04:00"; };
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  system.stateVersion = "26.05";
}
