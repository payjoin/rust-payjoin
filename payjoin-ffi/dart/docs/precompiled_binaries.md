# Precompiled binaries (maintainers)

This document describes how precompiled binaries are built, signed, and published for the Dart package.

## Overview

- CI builds and uploads precompiled binaries via a GitHub Actions workflow.
- Artifacts are tagged by the crate hash and uploaded to a GitHub release.
- Each binary is signed with an Ed25519 key; the public key is embedded in `pubspec.yaml`.
- The build hook downloads verified binaries when appropriate and falls back to local builds.

## Mode behavior

The `mode` configuration in app `pubspec.yaml` controls fallback behavior:

- `auto`: prefers local builds if `rustup` is detected; otherwise downloads precompiled binaries.
- `always`: requires precompiled binaries and skips local builds.
- `never`: always builds locally via the standard build hook.

## CI workflow

The workflow runs on manual dispatch or on a workflow call. It invokes:

```
dart run bin/build_tool.dart precompile-binaries ...
```

It builds macOS/iOS and Android targets.

## Release expectations

- The workflow creates/releases a GitHub release named `precompiled_<crateHash>`.
- If the release already exists, the workflow uploads missing assets without rebuilding.
- If `gh release view precompiled_<crateHash>` fails locally, rerun `dart run bin/build_tool.dart precompile-binaries ...`.

## How the download works

- The crate hash is computed from the Rust crate sources plus the plugin's `precompiled_binaries` config.
- The release tag is `precompiled_<crateHash>`.
- Assets are named `<targetTriple>_<libraryFileName>` with a matching `.sig` file.
- The hook downloads the signature and binary, verifies it, then places it in the build output.
- If any step fails, the hook builds locally via the standard build hook.

## Manual release (local)

Required environment variables:

- `PRIVATE_KEY` (Ed25519 private key, hex-encoded, 64 bytes)
- `GH_TOKEN` or `GITHUB_TOKEN` (GitHub token with release upload permissions)

Example:

```
dart run bin/build_tool.dart precompile-binaries \
  --manifest-dir="native" \
  --crate-package="payjoin-ffi-wrapper" \
  --repository="owner/repo" \
  --os=macos
```

## Troubleshooting & ops tips

- If `gh release view precompiled_<crateHash>` shows a release without expected assets, rerun the build locally.
- A stale crate hash (because sources or `precompiled_binaries` config changed) will point to a release that either doesn't exist yet or lacks current binaries; re-run `dart run bin/build_tool.dart hash --manifest-dir=native` to confirm the hash and rebuild with the same inputs.
- Use `gh release view precompiled_<crateHash> --json assets --jq '.assets[].name'` to inspect uploaded assets.
- Set `PAYJOIN_DART_PRECOMPILED_VERBOSE=1` to see download and verification details when debugging consumer builds.

## Configuration knobs

- `rust-toolchain.toml` controls the Rust channel and target list.
- `pubspec.yaml` under `payjoin.precompiled_binaries` must include:
  - `artifact_host` (owner/repo)
  - `public_key` (Ed25519 public key, hex-encoded, 32 bytes)

## Environment, keys, and secrets

- `PRIVATE_KEY`: 64-byte hex string (Ed25519 private key). Keep it out of source control.
- `PUBLIC_KEY`: Add the matching 32-byte hex public key to `pubspec.yaml`.
- `GH_TOKEN` / `GITHUB_TOKEN`: release upload permissions.
- `PAYJOIN_DART_PRECOMPILED_VERBOSE=1`: optional; shows download and verification details.

Generate a keypair with `dart run bin/build_tool.dart gen-key` and copy the printed `PRIVATE_KEY`/`PUBLIC_KEY` values. Rotate the pair if you ever suspect the signing key was exposed, and update every release’s config accordingly.

## Security reminder

- Treat the `PRIVATE_KEY` used for signing as highly sensitive; do not commit it to version control and rotate it immediately if you suspect compromise.
- Update the public key in `pubspec.yaml` if the private key is rotated so consumers can still verify downloads.
