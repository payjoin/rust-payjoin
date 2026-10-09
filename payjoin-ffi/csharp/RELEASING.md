# Releasing the Payjoin NuGet Package

Maintainer documentation for publishing the `Payjoin` package to nuget.org.
Consumer documentation lives in [`README.md`](README.md), which ships as the
package readme.

## Versioning

All published bindings share the payjoin-ffi version, starting with
0.25.0. Follow the [shared release instructions](../RELEASING.md) to bump
versions and publish using one signed FFI tag. Retained build metadata
identifies the wrapped payjoin core, and registries that omit metadata
publish the bare FFI version.

NuGet retains the historical `0.24.0-preview.1` release. The common
`0.25.0` release supersedes it as well as the independent C# sequence.

## Producing a release candidate

CI is the release path. On every pull request touching `payjoin-ffi/**`, the
`Build and Test CSharp` workflow:

1. builds release-profile native assets for each supported RID
   (`linux-arm64`, `linux-x64`, `osx-arm64`, `osx-x64`, `win-arm64`,
   `win-x64`),
2. generates production bindings (no `_test-utils`) and packs the `.nupkg`
   with all RID assets,
3. installs the package into a clean console app and runs a smoke test on
   each supported RID.

To cut a candidate, download the `payjoin-csharp-nuget-package` artifact from
the workflow run on the release commit in `master`. Do not pack from a
development machine for publication; a local pack only contains the native
assets present on that host.

## Release readiness checklist

Review before every publish to nuget.org. Grounded in the NuGet
[publish guide], [package authoring best practices], and
[native library packaging] documentation.

### Package correctness

- [ ] Every job of the `Build and Test CSharp` workflow is green on the
      release commit, including the per-RID smoke tests.
- [ ] `unzip -l Payjoin.<version>.nupkg` shows the expected layout:
  - `README.md`
  - `ref/net10.0/Payjoin.dll`
  - `runtimes/any/lib/net10.0/Payjoin.dll`
  - `runtimes/linux-arm64/native/libpayjoin_ffi.so`
  - `runtimes/linux-x64/native/libpayjoin_ffi.so`
  - `runtimes/osx-arm64/native/libpayjoin_ffi.dylib`
  - `runtimes/osx-x64/native/libpayjoin_ffi.dylib`
  - `runtimes/win-arm64/native/payjoin_ffi.dll`
  - `runtimes/win-x64/native/payjoin_ffi.dll`
- [ ] Native assets are release-profile builds without `_test-utils` (the
      pack step's validation target enforces both; confirm it ran in CI).
- [ ] The package is under nuget.org's 250 MB size limit.
- [ ] Package version in `Payjoin.csproj` carries the common FFI version
      and its `+payjoin-{version}` build metadata matches the wrapped
      payjoin core release.

### Metadata and trust

- [ ] README renders correctly (verify with nuget.org upload preview or the
      [readme preview] guidance) and its install command, support matrix, and
      minimal usage are accurate for this version.
- [ ] License expression, project URL, repository URL, and tags are present
      and correct in `Payjoin.csproj`.
- [ ] Release notes for this version exist (GitHub release or changelog
      entry) and breaking changes are called out — required for any version
      that changes the package model consumers depend on.
- [ ] Ownership of the `Payjoin` package ID on nuget.org is confirmed for the
      publishing account (nuget.org assigns ownership to the pushing account,
      not the `Authors` field).

### Publish security

- [ ] The nuget.org publishing account has two-factor authentication enabled.
- [ ] The push uses a scoped API key (push-only, `Payjoin` glob, short
      expiry) per [scoped API keys], or the `NUGET_API_KEY` environment
      variable (.NET SDK 10.0.300+) so the key never appears in shell
      history.

### Post-publish verification

- [ ] Package passes nuget.org validation and indexing (usually under 15
      minutes; the confirmation email arrives when it is listed).
- [ ] `dotnet new console && dotnet add package Payjoin --prerelease`
      restores, builds, and runs on at least one supported RID from the live
      feed.
- [ ] Listing on <https://www.nuget.org/packages/Payjoin> shows the readme,
      license, and repository metadata as intended.
- [ ] Decide whether older versions (for example the `0.0.1` placeholder)
      should be unlisted or deprecated now that a real release exists.

## Publishing

Follow the [shared release procedure](../RELEASING.md). The
`payjoin-ffi-<version>+payjoin-<core-version>` tag reruns this language's
build and smoke checks before publishing through the existing `release`
environment with OIDC. The package version must match the common FFI
version, and its core metadata must match the declared core dependency.

The GitHub release includes all language packages and
`SHA256SUMS`. Optional local signatures use
`SHA256SUMS.asc`. Verify installation from the registry and
check provenance with `gh attestation verify FILE -R payjoin/rust-payjoin`.

[trusted publishing]: https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing
