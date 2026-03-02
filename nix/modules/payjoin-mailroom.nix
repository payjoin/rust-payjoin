flake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.payjoin-mailroom;
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "payjoin-mailroom.toml" cfg.settings;
in
{
  options.services.payjoin-mailroom = {
    enable = lib.mkEnableOption "payjoin-mailroom, a combined payjoin directory and OHTTP relay";

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.system}.payjoin-mailroom;
      defaultText = lib.literalExpression "flake.packages.\${pkgs.system}.payjoin-mailroom";
      description = "The payjoin-mailroom package to use.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      description = ''
        Configuration for payjoin-mailroom, serialized to TOML.
        See config.example.toml for available options.
      '';
      example = lib.literalExpression ''
        {
          listener = "[::]:443";
          timeout = 30;
          acme = {
            domains = [ "payjo.in" ];
            contact = [ "mailto:admin@payjo.in" ];
          };
        }
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Additional environment variables to pass to the service.";
      example = {
        RUST_LOG = "debug";
      };
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File containing environment variables for the service.
        Useful for secrets like PJ_TELEMETRY__AUTH_TOKEN.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.payjoin-mailroom.settings = {
      storage_dir = lib.mkDefault "/var/lib/payjoin-mailroom";
    };

    systemd.services.payjoin-mailroom = {
      description = "Payjoin Mailroom";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        RUST_LOG = lib.mkDefault "info";
      }
      // cfg.environment;

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/payjoin-mailroom --config ${configFile}";
        DynamicUser = true;
        StateDirectory = "payjoin-mailroom";
        WorkingDirectory = "/var/lib/payjoin-mailroom";
        Restart = "on-failure";
        RestartSec = 5;

        # Allow binding to privileged ports (e.g. 443 for ACME)
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
      }
      // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      };
    };
  };
}
