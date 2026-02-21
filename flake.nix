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
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix2container = {
      url = "github:nlewo/nix2container";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      treefmt-nix,
      nix2container,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            rust-overlay.overlays.default
            (final: prev: {
              rustToolchains = {
                msrv = prev.rust-bin.stable.${msrv-version}.default;
                stable = prev.rust-bin.stable.latest.default;
                nightly = prev.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
              };
            })
          ];
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
            || (builtins.match ".*\\.mmdb$" path != null)
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

        # avoid release builds throughout for faster feedback from checks
        ciArgs = commonArgs // {
          CARGO_PROFILE = "nix-ci";
        };

        # use release profile for built packages
        releaseArgs = commonArgs // {
          CARGO_PROFILE = "release";
        };

        cargoArtifacts = builtins.mapAttrs (
          name: craneLib:
          craneLib.buildDepsOnly (
            releaseArgs
            // {
              name = "workspace-deps-${name}";
              cargoLock = cargoLock.${name};
            }
          )
        ) craneLibVersions;
        # use nix-ci profile for cargo artifacts
        cargoArtifactsCi = builtins.mapAttrs (
          name: craneLib:
          craneLib.buildDepsOnly (
            ciArgs
            // {
              name = "workspace-deps-ci-${name}";
              cargoLock = cargoLock.${name};
            }
          )
        ) craneLibVersions;

        treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

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
                releaseArgs
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
              "payjoin-mailroom" = "--features access-control,acme,telemetry";
            };

        # nix2container for building OCI/Docker images
        nix2containerPkgs = nix2container.packages.${system};

        # Helper to create a container image for a package
        mkContainerImage =
          name: pkg: tag:
          let
            releasePkg = pkg.overrideAttrs (final: prev: { CARGO_PROFILE = "release"; });
          in
          nix2containerPkgs.nix2container.buildImage {
            inherit tag;
            name = "docker.io/payjoin/${name}";
            copyToRoot = pkgs.buildEnv {
              name = "root";
              paths = [ releasePkg ];
              pathsToLink = [ "/bin" ];
            };
            config = {
              entrypoint = [ (pkgs.lib.getExe' releasePkg name) ];
            };
            maxLayers = 50;
          };

        containerImages =
          let
            envTag = builtins.getEnv "IMAGE_TAG";
            tag = if envTag != "" then envTag else (self.shortRev or "dirty");
          in
          {
            "payjoin-mailroom-image" = mkContainerImage "payjoin-mailroom" packages.payjoin-mailroom tag;
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
                cargo-fuzz
                bzip2 # needed for some machines to have access to libzip at runtime
                codespell
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
        packages =
          packages
          // containerImages
          // {
            nginx-with-stream = nginxWithStream;
          };
        devShells = devShells // {
          default = devShells.nightly;
        };
        formatter = treefmtEval.config.build.wrapper;
        checks =
          (pkgs.lib.mapAttrs' (
            name: craneLib:
            (pkgs.lib.nameValuePair "payjoin-workspace-nextest-${name}" (
              craneLib.cargoNextest (
                ciArgs
                // {
                  name = "payjoin-workspace-nextest-${name}";
                  cargoLock = cargoLock.${name};
                  cargoArtifacts = cargoArtifactsCi.${name};
                  partitions = 1;
                  partitionType = "count";
                  cargoExtraArgs = "--locked --workspace --all-features --exclude payjoin-fuzz";
                  NEXTEST_SHOW_PROGRESS = "none";
                  BITCOIND_EXE = nixpkgs.lib.getExe' pkgs.bitcoind "bitcoind";
                  NGINX_EXE = nixpkgs.lib.getExe' nginxWithStream "nginx";
                  nativeBuildInputs = [ nginxWithStream ];
                  doInstallCargoArtifacts = false;
                }
              )
            ))
          ) craneLibVersions

          )
          // {
            payjoin-workspace-machete = craneLibVersions.nightly.mkCargoDerivation (
              ciArgs
              // {
                pname = "payjoin-workspace-machete";
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifactsCi.nightly;
                nativeBuildInputs = [ pkgs.cargo-machete ];
                buildPhaseCargoCommand = "";
                checkPhaseCargoCommand = "cargo machete";
                doCheck = true;
              }
            );

            payjoin-workspace-clippy = craneLibVersions.nightly.cargoClippy (
              ciArgs
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifactsCi.nightly;
                cargoClippyExtraArgs = "--all-targets --all-features --keep-going -- --deny warnings";
              }
            );

            payjoin-workspace-doc = craneLibVersions.nightly.cargoDoc (
              ciArgs
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifactsCi.nightly;
              }
            );

            payjoin-workspace-fmt = craneLibVersions.nightly.cargoFmt (
              ciArgs
              // {
                inherit src;
                # cargoLock = cargoLock.nightly;
              }
            );

            formatting = treefmtEval.config.build.check self;

            quick = checkSuite "quick" (
              with self.outputs.checks.${system};
              [
                formatting
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
              ++ pkgs.lib.attrValues (
                builtins.mapAttrs (
                  _name: pkg:
                  pkg.overrideAttrs (
                    final: prev: {
                      CARGO_PROFILE = "nix-ci";
                      cargoArtifacts = cargoArtifactsCi.msrv;
                    }
                  )
                ) packages
              )
            );

            maintenance = checkSuite "maintenance" (
              with self.outputs.checks.${system};
              [
                payjoin-workspace-machete
                payjoin-workspace-clippy
                payjoin-workspace-doc
                formatting
              ]
            );
          };
      }
    );
}
