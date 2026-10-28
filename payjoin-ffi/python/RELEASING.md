# Releasing the payjoin Python package

Maintainer documentation for publishing the `payjoin` package to
[PyPI](https://pypi.org/project/payjoin/). Consumer documentation lives in
[`README.md`](README.md).

## Versioning

All published bindings share the payjoin-ffi version, starting with
0.25.0. Follow the [shared release instructions](../RELEASING.md) to bump
versions and publish using one signed FFI tag. The changelog entry names
the wrapped payjoin core.

## Producing the wheels

CI is the release path. On every bindings release and in the
`Daily language bindings` run on `master`, the `Build and Test Python`
workflow builds release wheels with
[`contrib/build-wheel.sh`](contrib/build-wheel.sh) (release profile, no
`_test-utils`) and smoke-installs them on every supported platform:

- `manylinux` x86_64, tagged by auditwheel with the glibc floor the binary
  actually satisfies, 2.17;
- macOS `universal2` (a fat x86_64 + arm64 dylib), combined from the two
  macOS slices.

Both libraries are built on Linux under the
[native build contract](../../contrib/native/README.md).

The wheels are tagged `py3-none` because the generated bindings load the
bundled library through `ctypes` and do not depend on a CPython ABI; any
CPython satisfying `requires-python` can install them.

## Publishing

Follow the [shared release procedure](../RELEASING.md). The
`payjoin-ffi-<version>` tag reruns this language's build and smoke checks
before publishing through the existing `release` environment with OIDC.
The package version must match the common FFI version.

The GitHub release includes all language packages and
`SHA256SUMS`. Optional local signatures use
`SHA256SUMS.asc`. Verify installation from the registry and
check provenance with `gh attestation verify FILE -R payjoin/rust-payjoin`.
