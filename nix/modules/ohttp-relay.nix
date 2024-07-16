self:
{
  config,
  pkgs,
  inputs,
  lib,
  ...
}:
with lib;
let
  cfg = config.services.ohttp-relay;
  socketPath = "/run/ohttp-relay/unix.sock";
  ohttpHTTPSPath = "/run/nginx/ohttp-https.sock";
  defaultUserGroup = "ohttprelay";
in
{
  options = {
    services.ohttp-relay = {
      package = mkOption {
        type = types.package;
        default = self.packages.${pkgs.system}.default;
      };
      relayHostname = mkOption { type = types.str; };
      gatewayOrigin = mkOption { type = types.str; };
      user = mkOption {
        type = types.str;
        default = defaultUserGroup;
        description = mdDoc "User account under which to run. Not created if not default.";
      };

      group = mkOption {
        type = types.str;
        default = cfg.user;
        description = mdDoc "Group under which to run. Not created if not default.";
      };
    };
  };

  config = {
    networking.firewall.allowedTCPPorts = [
      80
      443
    ];

    security.acme = {
      certs."${cfg.relayHostname}" = {
        group = "${config.services.nginx.group}";
        # NOTE: random port so that nix assertion doesn't complain:
        # https://github.com/NixOS/nixpkgs/blob/2819fffa7fa42156680f0d282c60d81e8fb185b7/nixos/modules/security/acme/default.nix#L950
        listenHTTP = "127.0.0.1:1360";
        extraLegoFlags = [
          "--tls"
          "--tls.port"
          "127.0.0.1:30443"
        ];
      };
    };

    services.nginx = {
      enable = true;
      virtualHosts = { };
      streamConfig = ''
        map $ssl_preread_alpn_protocols $is_acme {
          ~\bacme-tls/1\b 1;
          default 0;
        }

        map $is_acme $backend {
          1 acme;
          default ohttp-https;
        }

        upstream ohttp-https {
          server unix:${ohttpHTTPSPath};
        }

        upstream ohttp-relay {
          server unix:${socketPath};
        }

        upstream acme {
          server 127.0.0.1:30443;
        }

        server {
          listen 443;

          ssl_preread on;

          proxy_pass $backend;
        }

        server {
          listen 80;

          proxy_pass ohttp-relay;
        }

        server {
          listen unix:${ohttpHTTPSPath} ssl;

          ssl_certificate ${config.security.acme.certs."${cfg.relayHostname}".directory}/fullchain.pem;
          ssl_certificate_key ${config.security.acme.certs."${cfg.relayHostname}".directory}/key.pem;

          # START: Modern configuration
          # Ref: https://ssl-config.mozilla.org/#server=nginx&version=1.17.7&config=modern&openssl=1.1.1k&guideline=5.7
          ssl_session_timeout 1d;
          ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
          ssl_session_tickets off;

          ssl_protocols TLSv1.3;
          ssl_prefer_server_ciphers off;
          # END: Modern configuration

          proxy_pass ohttp-relay;
        }
      '';
    };

    systemd.services.ohttp-relay = {
      enable = true;
      description = "OHTTP Relay";
      wantedBy = [ "multi-user.target" ];

      after = [ "network-online.target" ];

      environment = {
        GATEWAY_ORIGIN = cfg.gatewayOrigin;
        UNIX_SOCKET = socketPath;
      };

      serviceConfig = {
        # Give group permissions so people in the group can hit the unix socket
        UMask = "0002";

        Type = "simple";

        User = cfg.user;
        Group = cfg.group;

        RuntimeDirectory = "ohttp-relay";

        ExecStart = "${cfg.package}/bin/ohttp-relay";
        PrivateTmp = true;
      };
    };

    users = {
      groups = optionalAttrs (cfg.group == "${defaultUserGroup}") {
        "${defaultUserGroup}" = { };
      };
      users = {
        "${config.services.nginx.user}" = {
          extraGroups = [ config.users.groups.ohttprelay.name ];
        };
      }
      // (optionalAttrs (cfg.user == "${defaultUserGroup}") {
        "${defaultUserGroup}" = {
          description = "OHTTP Relay user";
          isSystemUser = true;
          group = cfg.group;
        };
      });
    };
  };
}
