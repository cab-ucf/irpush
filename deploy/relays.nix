# The irpush relay, and optionally a stock iroh relay beside it, behind one :443 routed by SNI (TLS
# passes through untouched; each relay does its own Let's Encrypt). MSS clamped so every TCP segment fits WireGuard on a minimum-MTU (1280) path.
# Abuse bounds live here, not in iroh-relay (its accept_conn_* limits are unimplemented in 1.4.1, and
# behind the proxy it sees only 127.0.0.1): per source IP, nftables caps new connections and nginx
# concurrent ones; idle sockets close after 135 min; iroh-relay caps each client's bytes.
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.irpushRelays;
  iroh = cfg.irohDomain != null;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system};
  toml = pkgs.formats.toml { };
  mss = "1120"; # 1280 - IPv6/TCP inner (60) - WireGuard over IPv6 (80) - TCP options margin (20)
  hardened = {
    DynamicUser = true;
    Environment = "RUST_LOG=warn"; # no per-connection logs (client IPs, endpoint ids)
    Restart = "always";
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
    SystemCallFilter = [ "@system-service" ];
    SystemCallArchitectures = "native";
  };
  irohConf = toml.generate "iroh-relay.toml" {
    http_bind_addr = "0.0.0.0:80"; # captive-portal probes
    enable_quic_addr_discovery = true;
    enable_metrics = false;
    tls = {
      https_bind_addr = "127.0.0.1:8441";
      quic_bind_addr = "0.0.0.0:7842";
      hostname = cfg.irohDomain;
      cert_mode = "LetsEncrypt";
      contact = cfg.email;
      cert_dir = "/var/lib/iroh-relay";
    };
    limits.client.rx = { bytes_per_second = 4194304; max_burst_bytes = 16777216; };
  };
  pushConf = toml.generate "irpush-relay.toml" {
    http_bind_addr = "127.0.0.1:8082";
    # devices learn their public address here (for direct paths), unless a stock relay holds the port
    enable_quic_addr_discovery = !iroh;
    enable_metrics = false;
    tls = {
      https_bind_addr = "127.0.0.1:8442";
      hostname = cfg.irpushDomain;
      cert_mode = "LetsEncrypt";
      contact = cfg.email;
      cert_dir = "/var/lib/irpush-relay";
    } // lib.optionalAttrs (!iroh) { quic_bind_addr = "0.0.0.0:7842"; };
    # what one client can take: a relayed call fits, a flood does not (keys in /var/lib/irpush-relay/keys: no limit)
    limits.client.rx = { bytes_per_second = 4194304; max_burst_bytes = 16777216; };
  };
in {
  options.services.irpushRelays = {
    enable = lib.mkEnableOption "irpush relay (+ iroh relay)";
    irohDomain = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; }; # null: irpush only
    irpushDomain = lib.mkOption { type = lib.types.str; };
    email = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.iroh-relay = lib.mkIf iroh {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = hardened // {
        StateDirectory = "iroh-relay";
        WorkingDirectory = "/var/lib/iroh-relay";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ExecStart = "${pkg.iroh-relay}/bin/iroh-relay --config-path ${irohConf}";
        LimitNOFILE = 16384;
      };
    };

    # Open: anyone may connect, so every device homed here is reachable by everyone; limits bound abuse.
    systemd.services.irpush-relay = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = hardened // {
        StateDirectory = "irpush-relay";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/irpush-relay";
        CapabilityBoundingSet = [ "" ];
        Environment = [ "RUST_LOG=warn" "RELAY_KEYS=/var/lib/irpush-relay/keys" ];
        ExecStart = "${pkg.irpush-relay}/bin/iroh-relay --config-path ${pushConf}";
        LimitNOFILE = 16384;
      };
    };

    systemd.services.nginx.serviceConfig.LimitNOFILE = 65536;
    services.nginx = {
      enable = true;
      appendConfig = "worker_rlimit_nofile 65536;";
      eventsConfig = "worker_connections 16384;"; # two per proxied client
      streamConfig = ''
        limit_conn_zone $binary_remote_addr zone=perip:4m;
        map $ssl_preread_server_name $relay {
          ${cfg.irpushDomain} 127.0.0.1:8442;
          default ${if iroh then "127.0.0.1:8441" else "127.0.0.1:8442"};
        }
        server {
          listen 443;
          ssl_preread on;
          proxy_pass $relay;
          limit_conn perip 32; # phones of one household share an IP; a CGNAT'd crowd needs more
          proxy_timeout 135m;  # > irpush's 2 h max heartbeat and the relay's 130 min ping: closes half-open sockets
        }
      '';
    };

    networking.nftables = {
      enable = true;
      tables.conns = { # new connections per source (IPv6: per /64): burst 30, then 30 a minute
        family = "inet";
        content = ''
          set new4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; size 65536; }
          set new6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; size 65536; }
          chain in {
            type filter hook input priority filter; policy accept;
            tcp dport 443 ct state new update @new4 { ip saddr limit rate over 30/minute burst 30 packets } drop
            tcp dport 443 ct state new update @new6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 30/minute burst 30 packets } drop
          }
        '';
      };
      tables.mss = {
        family = "inet";
        content = ''
          chain in {
            type filter hook prerouting priority mangle;
            tcp dport 443 tcp flags & (syn | rst) == syn tcp option maxseg size > ${mss} tcp option maxseg size set ${mss}
          }
          chain out {
            type filter hook output priority mangle;
            tcp sport 443 tcp flags & (syn | ack) == syn | ack tcp option maxseg size > ${mss} tcp option maxseg size set ${mss}
          }
        '';
      };
    };
    networking.firewall = { allowedTCPPorts = [ 22 443 ] ++ lib.optional iroh 80; allowedUDPPorts = [ 7842 ]; };

    boot.kernel.sysctl = {
      "net.ipv4.tcp_mtu_probing" = 1; # recover from black holes the clamp cannot cover (e.g. WireGuard in WireGuard)
      "net.ipv4.tcp_base_mss" = 1024;
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
    };
  };
}
