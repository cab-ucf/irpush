# The only file to edit. DNS: A records for both names -> the VPS IP, before `make deploy`.
{
  irohDomain = "iroh.cxn.center";     # stock iroh relay, for apps' iroh connections
  irpushDomain = "irpush.cxn.center"; # irpush relay: long heartbeats, token-gated
  email = "admin@cxn.center";         # Let's Encrypt contact
  system = "x86_64-linux";            # Hetzner ARM (CAX): "aarch64-linux"
  disk = "/dev/vda";                  # DigitalOcean: /dev/vda, Hetzner: /dev/sda
  autoUpgrade = null;                 # e.g. "github:you/irpush#relay": nightly rebuild from your repo
  sshKeys = [ "ssh-ed25519 AAAA...replace-me relay-admin" ]; # a key used only for this VPS
}
