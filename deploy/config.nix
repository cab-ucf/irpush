# The only file to edit. DNS: an A record for irpushDomain (and irohDomain, if set) -> the VPS IP,
# before `make deploy`.
{
  irpushDomain = "irpush.cxn.center"; # irpush relay: long heartbeats
  irohDomain = null;                  # e.g. "iroh.cxn.center" to run a stock iroh relay here too
  email = "admin@cxn.center";         # Let's Encrypt contact
  system = "x86_64-linux";            # Hetzner ARM (CAX): "aarch64-linux"
  disk = "/dev/vda";                  # DigitalOcean: /dev/vda, Hetzner: /dev/sda
  autoUpgrade = null;                 # e.g. "github:you/irpush#relay": nightly rebuild from your repo
  sshKeys = [ "ssh-ed25519 AAAA...replace-me relay-admin" ]; # a key used only for this VPS
}
