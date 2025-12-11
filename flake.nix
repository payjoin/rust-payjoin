{
  description = "rust-payjoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        msrv-version = "1.85.0";

        nginxWithStream = pkgs.nginxMainline.overrideAttrs (oldAttrs: {
          configureFlags = oldAttrs.configureFlags ++ [
            "--with-stream"
            "--with-stream_ssl_module"
            "--error-log-path=/dev/null"
          ];
        });
        rustVersions =
          with pkgs.rust-bin;
          builtins.mapAttrs
            (
              _name: rust-bin:
              rust-bin.override {
                extensions = [
                  "rust-src"
                  "rustfmt"
                  "llvm-tools-preview"
                ];
              }
            )
            {
              msrv = stable.${msrv-version}.default;
              stable = stable.latest.default;
              nightly = fromRustupToolchainFile ./rust-toolchain.toml;
            };

        # Use crane to define nix packages for the workspace crate
        # based on https://crane.dev/examples/quick-start-workspace.html
        # default to nightly rust toolchain in crane, mainly due to rustfmt difference
        craneLibVersions = builtins.mapAttrs (
          name: rust-bin: (crane.mkLib pkgs).overrideToolchain (_: rust-bin)
        ) rustVersions;

        src = nixpkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            (builtins.match ".*nginx.conf.template$" path != null)
            || (craneLibVersions.msrv.filterCargoSources path type);
          name = "source";
        };
        cargoLock = rec {
          default = recent; # see also #454
          recent = ./Cargo-recent.lock;
          minimal = ./Cargo-minimal.lock;
          msrv = minimal;
          stable = default;
          nightly = recent;
        };
        commonArgs = {
          inherit src;
          strictDeps = true;

          # provide fallback name & version for workspace related derivations
          # this is mainly to silence warnings from crane about providing a stub
          # value overridden in per-crate packages with info from Cargo.toml
          pname = "workspace";
          version = "no-version";

          # tell bitcoind crate not to try to download during build
          BITCOIND_SKIP_DOWNLOAD = 1;
        };

        cargoArtifacts = builtins.mapAttrs (
          name: craneLib:
          craneLib.buildDepsOnly (
            commonArgs
            // {
              name = "workspace-deps-${name}";
              cargoLock = cargoLock.${name};
            }
          )
        ) craneLibVersions;

        fileSetForCrate =
          subdir:
          pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              (craneLibVersions.msrv.fileset.commonCargoSources subdir)
            ];
          };

        packages =
          builtins.mapAttrs
            (
              name: extraArgs:
              # build packages with MSRV toolchain by default, since the builds are
              # mostly for testing purposes
              craneLibVersions.msrv.buildPackage (
                commonArgs
                // craneLibVersions.msrv.crateNameFromCargoToml {
                  cargoToml = builtins.toPath "${./.}/${name}/Cargo.toml";
                }
                // {
                  cargoLock = cargoLock.msrv;
                  cargoArtifacts = cargoArtifacts.msrv;
                  doCheck = false; # skip testing, since that's done in a separate flake check
                  cargoExtraArgs = "--locked -p ${name} ${extraArgs}";
                  inherit src;
                }
              )
            )
            {
              "payjoin" = "--features v2";
              "payjoin-cli" = "--features v1,v2";
              "payjoin-directory" = "";
              "ohttp-relay" = "";
            };

        devShells = builtins.mapAttrs (
          _name: craneLib:
          craneLib.devShell {
            packages =
              with pkgs;
              [
                cargo-edit
                cargo-nextest
                cargo-watch
                rust-analyzer
                dart
                nginxWithStream
              ]
              ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
                cargo-llvm-cov
              ];
          }
        ) craneLibVersions;

        simpleCheck =
          args:
          pkgs.stdenvNoCC.mkDerivation (
            {
              doCheck = true;
              dontFixup = true;
              installPhase = "mkdir $out";
            }
            // args
          );

        dummySrc = pkgs.runCommand "dummy src" { } "mkdir $out";
        checkSuite =
          name: buildInputs:
          simpleCheck {
            inherit name;
            inherit buildInputs;
            src = dummySrc;
          };
      in
      {
        packages = packages // {
          nginx-with-stream = nginxWithStream;
        };
        devShells = devShells // {
          default = devShells.nightly;
        };
        formatter = pkgs.nixfmt-tree;
        checks =
          packages
          // (pkgs.lib.mapAttrs' (
            name: craneLib:
            (pkgs.lib.nameValuePair "payjoin-workspace-nextest-${name}" (
              craneLib.cargoNextest (
                commonArgs
                // {
                  name = "payjoin-workspace-nextest-${name}";
                  cargoLock = cargoLock.${name};
                  cargoArtifacts = cargoArtifacts.${name};
                  partitions = 1;
                  partitionType = "count";
                  cargoExtraArgs = "--locked --all-features";
                  BITCOIND_EXE = nixpkgs.lib.getExe' pkgs.bitcoind "bitcoind";
                  nativeBuildInputs = [ nginxWithStream ];
                }

              )
            ))
          ) craneLibVersions

          )
          // {
            payjoin-workspace-machete = craneLibVersions.nightly.mkCargoDerivation (
              commonArgs
              // {
                pname = "payjoin-workspace-machete";
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifacts.nightly;
                nativeBuildInputs = [ pkgs.cargo-machete ];
                buildPhaseCargoCommand = "";
                checkPhaseCargoCommand = "cargo machete";
                doCheck = true;
              }
            );

            payjoin-workspace-clippy = craneLibVersions.nightly.cargoClippy (
              commonArgs
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifacts.nightly;
                cargoClippyExtraArgs = "--all-targets --all-features --keep-going -- --deny warnings";
              }
            );

            payjoin-workspace-doc = craneLibVersions.nightly.cargoDoc (
              commonArgs
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifacts.nightly;
              }
            );

            payjoin-workspace-fmt = craneLibVersions.nightly.cargoFmt (
              commonArgs
              // {
                inherit src;
                # cargoLock = cargoLock.nightly;
              }
            );

            nix-fmt-check = simpleCheck {
              name = "nix-fmt-check";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [ ".nix" ];
              nativeBuildInputs = [ pkgs.nixfmt-tree ];
              checkPhase = ''
                treefmt --ci --tree-root .
              '';
            };

            shfmt = simpleCheck rec {
              name = "shfmt";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [ ".sh" ];
              nativeBuildInputs = [ pkgs.shfmt ];
              checkPhase = ''
                shfmt -d -s -i 4 -ci ${src}
              '';
            };

            shellcheck = simpleCheck rec {
              name = "shellcheck";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [ ".sh" ];
              nativeBuildInputs = [
                pkgs.shellcheck
                pkgs.findutils
              ];
              checkPhase = ''
                find "${src}" -name '*.sh' -print0 | xargs -0 shellcheck -x
              '';
            };

            quick = checkSuite "quick" (
              with self.outputs.checks.${system};
              [
                shfmt
                shellcheck
                nix-fmt-check
              ]
            );

            slow = checkSuite "slow" (
              with self.outputs.checks.${system};
              [
                nightly
                stable
                msrv
              ]
            );

            nightly = checkSuite "nightly" (
              with self.outputs.checks.${system};
              [
                payjoin-workspace-nextest-nightly
              ]
            );

            stable = checkSuite "stable" (
              with self.outputs.checks.${system};
              [
                payjoin-workspace-nextest-stable
              ]
            );

            msrv = checkSuite "msrv" (
              with self.outputs.checks.${system};
              [
                payjoin-workspace-nextest-msrv
              ]
              ++ pkgs.lib.attrValues packages
            );
          };
      }
    );
}
