{
  description = "rust-payjoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [rust-overlay.overlays.default];
        };

        msrv = "1.63.0";
        rustVersions = with pkgs.rust-bin;
          builtins.mapAttrs (_name: rust-bin:
            rust-bin.override {
              extensions = ["rust-src" "rustfmt"];
            })
          {
            msrv = stable.${msrv}.default;
            stable = stable.latest.default;
            nightly = nightly.latest.default;
          };

        mkShell = rust-bin:
          pkgs.mkShell {
            packages = with pkgs; [
              (rust-bin.override {
                extensions = ["rust-src" "rustfmt"];
              })
            ];
          };
        devShells = builtins.mapAttrs (_name: rustVersion: mkShell rustVersion) rustVersions;

        simpleCheck = args:
          pkgs.stdenvNoCC.mkDerivation ({
              doCheck = true;
              dontFixup = true;
              installPhase = "mkdir $out";
            }
            // args);
      in {
        devShells = devShells // {default = devShells.nightly;};
        formatter = pkgs.alejandra;
        checks = {
          nix-fmt-check = simpleCheck {
            name = "nix-fmt-check";
            src = pkgs.lib.sources.sourceFilesBySuffices ./. [".nix"];
            nativeBuildInputs = [pkgs.alejandra];
            checkPhase = ''
              alejandra -c .
            '';
          };
        };
      }
    );
}
