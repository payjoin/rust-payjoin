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
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
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
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
    }:
    {
      nixosModules.payjoin-mailroom = import ./nix/modules/payjoin-mailroom.nix self;
    }
    // flake-utils.lib.eachDefaultSystem (
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
            || (builtins.match ".*\\.html$" path != null)
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

        vendoredDeps = builtins.mapAttrs (
          name: _:
          craneLibVersions.stable.vendorCargoDeps {
            cargoLock = cargoLock.${name};
            inherit src;
          }
        ) craneLibVersions;

        # nixpkgs' blockstream-electrs build runs a flaky `test_electrum`
        # integration test that fails on some sandboxes. Skip its checks.
        blockstreamElectrs = pkgs.blockstream-electrs.overrideAttrs (_: {
          doCheck = false;
        });

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
          # same for electrsd (used in payjoin-cli esplora e2e tests)
          ELECTRSD_SKIP_DOWNLOAD = 1;
        };

        # Per-toolchain common args that include pre-vendored deps
        commonArgsFor =
          name:
          commonArgs
          // {
            cargoVendorDir = vendoredDeps.${name};
          };

        # use nix-ci profile for fast checks
        ciArgsFor =
          name:
          commonArgsFor name
          // {
            CARGO_PROFILE = "nix-ci";
          };

        cargoArtifacts = builtins.mapAttrs (
          name: craneLib:
          craneLib.buildDepsOnly (
            commonArgsFor name
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
            ciArgsFor name
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
                commonArgsFor "msrv"
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
            tag =
              if envTag == "master" then
                self.shortRev
              else if envTag != "" then
                envTag
              else
                self.shortRev or "dirty";
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
            BITCOIND_EXE = pkgs.lib.getExe' pkgs.bitcoind "bitcoind";
            BITCOIND_SKIP_DOWNLOAD = 1;
            ELECTRS_EXE = pkgs.lib.getExe' blockstreamElectrs "electrs";
            ELECTRSD_SKIP_DOWNLOAD = 1;
          }
        ) craneLibVersions;

        # uv2nix: load the Python workspace from payjoin-ffi/python/uv.lock
        pythonWorkspace = uv2nix.lib.workspace.loadWorkspace {
          workspaceRoot = ./payjoin-ffi/python;
        };

        pythonOverlay = pythonWorkspace.mkPyprojectOverlay {
          sourcePreference = "wheel";
        };

        pythonSet =
          (pkgs.callPackage pyproject-nix.build.packages {
            python = pkgs.python3;
          }).overrideScope
            (
              nixpkgs.lib.composeManyExtensions [
                pyproject-build-systems.overlays.wheel
                pythonOverlay
              ]
            );

        # Build a virtualenv with dependency groups from uv.lock, excluding the payjoin package, which is built separately
        pythonVenv = pythonSet.mkVirtualEnv "payjoin-python-dev-env" (
          builtins.removeAttrs pythonWorkspace.deps.all [ "payjoin" ]
        );

        pythonDevShell = pkgs.mkShell {
          name = "python-dev";
          packages = [
            pythonVenv
            pkgs.uv
            rustVersions.msrv
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.pkg-config
            pkgs.openssl
            pkgs.clang
          ];

          env = {
            # Prevent uv from downloading Python or managing the venv itself, nix provides both;
            UV_NO_SYNC = "1";
            UV_PYTHON_DOWNLOADS = "never";
          };

          shellHook = ''
            # to avoid host/global Python path leaking into the Nix env
            unset PYTHONPATH
          '';
        };

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
          python = pythonDevShell;
        };
        formatter = treefmtEval.config.build.wrapper;
        checks =
          (pkgs.lib.mapAttrs' (
            name: craneLib:
            (pkgs.lib.nameValuePair "payjoin-workspace-nextest-${name}" (
              craneLib.cargoNextest (
                ciArgsFor name
                // {
                  name = "payjoin-workspace-nextest-${name}";
                  cargoLock = cargoLock.${name};
                  cargoArtifacts = cargoArtifactsCi.${name};
                  partitions = 1;
                  partitionType = "count";
                  cargoExtraArgs = "--locked --workspace --all-features --exclude payjoin-fuzz";
                  BITCOIND_EXE = nixpkgs.lib.getExe' pkgs.bitcoind "bitcoind";
                  ELECTRS_EXE = nixpkgs.lib.getExe' blockstreamElectrs "electrs";
                  NGINX_EXE = nixpkgs.lib.getExe' nginxWithStream "nginx";
                  nativeBuildInputs = [
                    nginxWithStream
                    blockstreamElectrs
                  ];
                  doInstallCargoArtifacts = false;
                }
              )
            ))
          ) craneLibVersions

          )
          // {
            payjoin-workspace-machete = craneLibVersions.nightly.mkCargoDerivation (
              ciArgsFor "nightly"
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
              ciArgsFor "nightly"
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifactsCi.nightly;
                cargoClippyExtraArgs = "--all-targets --all-features --keep-going -- --deny warnings";
              }
            );

            payjoin-workspace-doc = craneLibVersions.nightly.cargoDoc (
              ciArgsFor "nightly"
              // {
                cargoLock = cargoLock.nightly;
                cargoArtifacts = cargoArtifactsCi.nightly;
              }
            );

            payjoin-workspace-fmt = craneLibVersions.nightly.cargoFmt (
              ciArgsFor "nightly"
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
