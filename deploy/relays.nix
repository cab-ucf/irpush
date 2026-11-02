# Two relays behind one :443, routed by SNI (TLS passes through untouched; each relay does its own
# Let's Encrypt). MSS clamped so every TCP segment fits WireGuard on a minimum-MTU (1280) path.
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.irpushRelays;
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
    limits = { accept_conn_limit = 50.0; accept_conn_burst = 200; client.rx = { bytes_per_second = 4194304; max_burst_bytes = 16777216; }; };
  };
  pushConf = toml.generate "irpush-relay-base.toml" {
    http_bind_addr = "127.0.0.1:8082";
    enable_quic_addr_discovery = false;
    enable_metrics = false;
    tls = {
      https_bind_addr = "127.0.0.1:8442";
      hostname = cfg.irpushDomain;
      cert_mode = "LetsEncrypt";
      contact = cfg.email;
      cert_dir = "/var/lib/irpush-relay";
    };
    # pushes are tiny; this bounds what anyone holding the (app-embedded) token can take
    limits = { accept_conn_limit = 20.0; accept_conn_burst = 100; client.rx = { bytes_per_second = 65536; max_burst_bytes = 1048576; }; };
  };
in {
  options.services.irpushRelays = {
    enable = lib.mkEnableOption "iroh relay + irpush relay";
    irohDomain = lib.mkOption { type = lib.types.str; };
    irpushDomain = lib.mkOption { type = lib.types.str; };
    email = lib.mkOption { type = lib.types.str; };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.iroh-relay = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = hardened // {
        StateDirectory = "iroh-relay";
        WorkingDirectory = "/var/lib/iroh-relay";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ExecStart = "${pkg.iroh-relay}/bin/iroh-relay --config-path ${irohConf}";
      };
    };

    # Tokens: /var/lib/irpush-relay/tokens, one per line (several during rotation). Never in the store.
    systemd.services.irpush-relay = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = [ pkgs.openssl pkgs.coreutils pkgs.gnused ];
      preStart = ''
        t=$STATE_DIRECTORY/tokens
        [ -s "$t" ] || { umask 077; openssl rand -hex 32 > "$t"; }
        { cat ${pushConf}; printf '\n[access]\nshared_token = [%s]\n' "$(sed 's/.*/"&"/' "$t" | paste -sd, -)"; } > "$RUNTIME_DIRECTORY/relay.toml"
      '';
      serviceConfig = hardened // {
        StateDirectory = "irpush-relay";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "irpush-relay";
        RuntimeDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/irpush-relay";
        CapabilityBoundingSet = [ "" ];
        ExecStart = "${pkg.irpush-relay}/bin/iroh-relay --config-path /run/irpush-relay/relay.toml";
      };
    };

    services.nginx = {
      enable = true;
      streamConfig = ''
        map $ssl_preread_server_name $relay {
          ${cfg.irpushDomain} 127.0.0.1:8442;
          default 127.0.0.1:8441;
        }
        server {
          listen 443;
          ssl_preread on;
          proxy_pass $relay;
          proxy_timeout 1h; # > irpush's 28 min max heartbeat (default 10 min would cut idle sockets)
        }
      '';
    };

    networking.nftables = {
      enable = true;
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
    networking.firewall = { allowedTCPPorts = [ 22 80 443 ]; allowedUDPPorts = [ 7842 ]; };

    boot.kernel.sysctl = {
      "net.ipv4.tcp_mtu_probing" = 1; # recover from black holes the clamp cannot cover (e.g. WireGuard in WireGuard)
      "net.ipv4.tcp_base_mss" = 1024;
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
    };
  };
}
