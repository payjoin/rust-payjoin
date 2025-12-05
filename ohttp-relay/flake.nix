{
  description = "Build a cargo project without extra checks";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    crane = {
      url = "github:ipetkov/crane";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        craneLib = crane.mkLib pkgs;

        nginxWithStream = pkgs.nginxMainline.overrideAttrs (oldAttrs: {
          configureFlags = oldAttrs.configureFlags ++ [
            "--with-stream"
            "--with-stream_ssl_module"
            "--error-log-path=/dev/null"
          ];
        });

        ohttp-relay = craneLib.buildPackage {
          src = pkgs.lib.cleanSourceWith {
            src = craneLib.path ./.;
            filter = path: type: builtins.match ".*\\.template$" path != null || craneLib.filterCargoSources path type;
          };
          strictDeps = true;

          buildInputs = [
            nginxWithStream
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
          ];

          preBuild = ''
            export PATH=${nginxWithStream}/bin:$PATH
          '';
        };
      in
      {
        checks = {
          inherit ohttp-relay;
        };

        packages.nginx-with-stream = nginxWithStream;
        packages.default = ohttp-relay;

        apps.default = flake-utils.lib.mkApp {
          drv = ohttp-relay;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          packages = [
            nginxWithStream
            pkgs.rustup
          ];

          shellHook = ''
            rustup default nightly
            rustup component add rust-src
            export PATH=${pkgs.rustup}/bin:$PATH
          '';
        };
      });
}
