# Releasing the payjoin Python package

Maintainer documentation for publishing the `payjoin` package to
[PyPI](https://pypi.org/project/payjoin/). Consumer documentation lives in
[`README.md`](README.md).

## Versioning

- The package version is the `payjoin-ffi` crate version: `setup.py` reads
  it from `payjoin-ffi/Cargo.toml` at build time, so a release always
  requires the crate version to be correct first.
- There is no separate Python version to maintain: the publish job derives
  the version from the built wheels and refuses to publish if it does not
  match the pushed tag.

## Producing the wheels

CI is the release path. On every pull request touching `payjoin-ffi/**`,
the `Build and Test Python` workflow builds release wheels with
[`contrib/build-wheel.sh`](contrib/build-wheel.sh) (release profile, no
`_test-utils`) and smoke-installs them on every supported platform:

- `manylinux` x86_64, tagged by auditwheel with the glibc floor the binary
  actually satisfies;
- macOS `universal2` (a fat x86_64 + arm64 dylib), cross-compiled from the
  Linux host with cargo-zigbuild, so the dylib links the Apple SDK stubs
  zig bundles and records system install names rather than nix store paths.

The wheels are tagged `py3-none` because the generated bindings load the
bundled library through `ctypes` and do not depend on a CPython ABI; any
CPython satisfying `requires-python` can install them.

## Publishing

1. Confirm every `Build and Test Python` job is green on the release
   commit in `master`, including the per-platform smoke tests.
2. Tag that commit `payjoin-python-<version>`, where `<version>` is the
   `payjoin-ffi` crate version exactly. The tag must be annotated and
   signed by a maintainer key in `contrib/release/keys/`, and the tagged
   commit must be on `master`; `verify-tag` refuses to publish otherwise.

   ```shell
   git tag -s payjoin-python-0.24.0 -m payjoin-python-0.24.0
   git push upstream payjoin-python-0.24.0
   ```

   The tag reruns the full build/wheel/smoke graph at the tagged commit,
   then `publish-pypi` verifies the tag matches the built wheels, attests
   build provenance, and uploads through PyPI
   [trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC)
   with PEP 740 attestations, so no long-lived token is stored anywhere.
   The job runs in the `release` environment: approve the paused run before
   anything reaches the registry.

3. `github-release` attaches the wheels and a generated `SHA256SUMS` to
   the tag's GitHub release. Optionally sign `SHA256SUMS` locally and
   upload `SHA256SUMS.asc`.
4. Verify the publication: the PyPI listing shows the new version,
   `pip install payjoin==<version>` resolves on a supported platform, and
   `gh attestation verify <wheel> -R payjoin/rust-payjoin` passes against
   a release asset.
