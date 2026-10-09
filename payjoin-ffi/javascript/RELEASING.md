# Releasing the payjoin npm package

Follow the [shared bindings release instructions](../RELEASING.md) for
version bumps, registry configuration, tagging, and recovery after partial
publication. One `payjoin-ffi-<version>+payjoin-<core-version>` tag starts
all existing binding publishers.

## Versioning

Starting with 0.25.0, `package.json` uses the common FFI version. Its
`releaseTag` field appends the wrapped payjoin core as build metadata.
Keep both version entries in `package-lock.json` synchronized. npm
publishes the bare version, so changing only metadata requires another
common version bump.

## Package checks

The JavaScript workflow builds production wasm and compiled TypeScript,
packs the tarball with `contrib/pack.sh`, and smoke tests installation on
Linux and macOS. The package ships only `dist/` and is platform independent.
The publishing job compares the tag with the packed artifact, attests it,
and publishes through npm trusted publishing in the `release` environment.

The shared GitHub release includes the tarball and
`SHA256SUMS`. An optional local signature is named
`SHA256SUMS.asc`. Verify the registry version, its provenance
badge, and `gh attestation verify FILE -R payjoin/rust-payjoin`.
