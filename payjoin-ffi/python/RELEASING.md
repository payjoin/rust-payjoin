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
  Linux host with cargo-zigbuild like the C# native assets, so the dylib
  links the Apple SDK stubs zig bundles and records system install names
  rather than nix store paths.

The wheels are tagged `py3-none` because the generated bindings load the
bundled library through `ctypes` and do not depend on a CPython ABI; any
CPython satisfying `requires-python` can install them.

## Publishing

1. Confirm every `Build and Test Python` job is green on the release
   commit in `master`, including the per-platform smoke tests.
2. Tag that commit `payjoin-python-<version>`, where `<version>` is the
   `payjoin-ffi` crate version exactly, and push the tag:

   ```shell
   git tag payjoin-python-0.24.0
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
   upload `SHA256SUMS.asc`; never place a GPG key on a runner.
4. Verify the publication: the PyPI listing shows the new version,
   `pip install payjoin==<version>` resolves on a supported platform, and
   `gh attestation verify <wheel> -R payjoin/rust-payjoin` passes against
   a release asset.

One-time setup is account and repository configuration, not part of the
per-release flow: the PyPI trusted publisher for the `payjoin` project
(GitHub Actions, repository `payjoin/rust-payjoin`, workflow file
`python.yml`, environment `release`), and the `release` GitHub Actions
environment with required reviewers.

## Manual fallback

Use only if the CI publish path is unavailable. Requires maintainer rights
on the PyPI project and an account with two-factor authentication. Build
each platform's wheel on matching hardware, since a wheel only bundles
the native library built on that host:

```shell
nix develop .#python -c bash ./payjoin-ffi/python/contrib/build-wheel.sh
uv publish payjoin-ffi/python/dist/*.whl
```

A manual upload carries no attestations; prefer republishing through CI
for anything consumers will install.
