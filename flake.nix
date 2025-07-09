{
  description = "rust-payjoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    crane,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [rust-overlay.overlays.default];
        };

        msrv = "1.85.0";
        rustVersions = with pkgs.rust-bin;
          builtins.mapAttrs (_name: rust-bin:
            rust-bin.override {
              extensions = ["rust-src" "rustfmt" "llvm-tools-preview"];
            })
          {
            msrv = stable.${msrv}.default;
            stable = stable.latest.default;
            nightly = nightly.latest.default;
          };

        # Use crane to define nix packages for the workspace crate
        # based on https://crane.dev/examples/quick-start-workspace.html
        # default to nightly rust toolchain in crane, mainly due to rustfmt difference
        craneLibVersions = builtins.mapAttrs (name: rust-bin: (crane.mkLib pkgs).overrideToolchain (_: rust-bin)) rustVersions;
        craneLib = craneLibVersions.nightly;
        src = craneLib.cleanCargoSource ./.;
        commonArgs = {
          inherit src;
          strictDeps = true;

          # provide fallback name & version for workspace related derivations
          # this is mainly to silence warnings from crane about providing a stub
          # value overridden in per-crate packages with info from Cargo.toml
          pname = "workspace";
          version = "no-version";

          # default to recent dependency versions
          # TODO add overrides for minimal lockfile, once #454 is resolved
          cargoLock = ./Cargo-recent.lock;

          # tell bitcoind crate not to try to download during build
          BITCOIND_SKIP_DOWNLOAD = 1;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        individualCrateArgs =
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false; # skip testing, since that's done in flake check
          };

        fileSetForCrate = subdir:
          pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              (craneLib.fileset.commonCargoSources subdir)
            ];
          };

        packages =
          builtins.mapAttrs (
            name: extraArgs:
              craneLib.buildPackage (individualCrateArgs
                // craneLib.crateNameFromCargoToml {cargoToml = builtins.toPath "${./.}/${name}/Cargo.toml";}
                // {
                  cargoExtraArgs = "--locked -p ${name} ${extraArgs}";
                  inherit src;
                })
          ) {
            "payjoin" = "--features v2";
            "payjoin-cli" = "--features v1,v2";
            "payjoin-directory" = "";
          };

        # Python-specific configuration
        pythonVersion = pkgs.python3;
        pythonEnv = pythonVersion.withPackages (ps: with ps; [
          virtualenv
          pip
        ]);

        # Determine platform for generate script
        supportedPlatforms = {
          "x86_64-linux" = "linux";
          "aarch64-linux" = "linux";
          "x86_64-darwin" = "macos";
          "aarch64-darwin" = "macos";
        };
        platform = supportedPlatforms.${system} or (throw "Unsupported platform: ${system}. Supported platforms: ${builtins.concatStringsSep ", " (builtins.attrNames supportedPlatforms)}");

        # Python devShell
        pythonDevShell = pkgs.mkShell {
          name = "python-dev";
          buildInputs = with pkgs; [
            pythonEnv
            bash
          ];

          # Environment variables and shell hook
          shellHook = ''
            export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [pkgs.openssl]}:$LD_LIBRARY_PATH
            cd payjoin-ffi/python
            # Create and activate virtual environment
            python -m venv venv
            source venv/bin/activate
            # Install dependencies, allowing PyPI fetches for version mismatches
            pip install --requirement requirements.txt --requirement requirements-dev.txt
            # Generate bindings, setting PYBIN to the venv's python binary
            export PYBIN=./venv/bin/python
            bash ./scripts/generate_${platform}.sh
            # Set CARGO_TOML_PATH for setup.py
            export CARGO_TOML_PATH=${./.}/Cargo.toml
            # Build the wheel
            python setup.py bdist_wheel --verbose

            # Install payjoin
            pip install ./dist/payjoin-*.whl
          '';
        };

        devShells = builtins.mapAttrs (_name: craneLib:
          craneLib.devShell {
            packages = with pkgs; [
              cargo-edit
              cargo-nextest
              cargo-watch
              rust-analyzer
            ] ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
              cargo-llvm-cov
            ];
          })
        craneLibVersions;

        simpleCheck = args:
          pkgs.stdenvNoCC.mkDerivation ({
              doCheck = true;
              dontFixup = true;
              installPhase = "mkdir $out";
            }
            // args);
      in {
        packages = packages;
        devShells = devShells // {
          default = devShells.nightly;
          python = pythonDevShell;
        };
        formatter = pkgs.alejandra;
        checks =
          packages
          // {
            payjoin-workspace-nextest = craneLib.cargoNextest (commonArgs
              // {
                inherit cargoArtifacts;
                partitions = 1;
                partitionType = "count";
                # TODO also run integration tests
                # this needs --all-features to enable io,_danger_local_https features
                # unfortunately this can't yet work because running docker inside the nix sandbox is not possible,
                # which precludes use of the redis test container
                # cargoExtraArgs = "--locked --all-features";
                # buildInputs = [ pkgs.bitcoind ]; # not verified to work
              });

            payjoin-workspace-nextest-msrv = craneLibVersions.msrv.cargoNextest (commonArgs
              // {
                cargoArtifacts = craneLibVersions.msrv.buildDepsOnly commonArgs;
                partitions = 1;
                partitionType = "count";
              });

            payjoin-workspace-clippy = craneLib.cargoClippy (commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features --keep-going -- --deny warnings";
              });

            payjoin-workspace-doc = craneLib.cargoDoc (commonArgs
              // {
                inherit cargoArtifacts;
              });

            payjoin-workspace-fmt = craneLib.cargoFmt (commonArgs
              // {
                inherit src;
              });

            nix-fmt-check = simpleCheck {
              name = "nix-fmt-check";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [".nix"];
              nativeBuildInputs = [pkgs.alejandra];
              checkPhase = ''
                alejandra -c .
              '';
            };

            shfmt = simpleCheck rec {
              name = "shell-checks";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [".sh"];
              nativeBuildInputs = [pkgs.shfmt];
              checkPhase = ''
                shfmt -d -s -i 4 -ci ${src}
              '';
            };

            shellcheck = simpleCheck rec {
              name = "shell-checks";
              src = pkgs.lib.sources.sourceFilesBySuffices ./. [".sh"];
              nativeBuildInputs = [pkgs.shellcheck];
              checkPhase = ''
                shellcheck -x ${src}
              '';
            };
          };
      }
    );
}
