# Releasing the Payjoin NuGet Package

Maintainer documentation for publishing the `Payjoin` package to nuget.org.
Consumer documentation lives in [`README.md`](README.md), which ships as the
package readme.

## Versioning

- The package version is set in `Payjoin.csproj` (`<Version>`).
- It is the package's own semantic version, independent of the
  `payjoin-ffi` crate version. The language bindings follow a
  `{version}+payjoin-{version}` convention: the [SemVer] build metadata
  names the wrapped payjoin core release, so `0.1.0+payjoin-1.0.0`
  packages payjoin 1.0.0. NuGet accepts build metadata per its
  [package versioning] guidance but ignores it for version comparison
  and strips it from the `.nupkg` filename, so the package identity is
  the bare version.
- Bump `MAJOR.MINOR.PATCH` for C# API changes, and update the build
  metadata whenever the wrapped payjoin core version changes.
- A release that only changes the wrapped payjoin core version still
  needs at least a patch bump: the package identity ignores the build
  metadata, and nuget.org rejects republishing an identity that
  already exists.
- Versions up to `0.24.0-preview.1` tracked the `payjoin-ffi` crate
  version instead. They predate this scheme and are unlisted on
  nuget.org so they do not resolve as the latest version.
- `Payjoin.csproj` is the only place the version is maintained: the CI smoke
  test derives the version from the packed artifact.

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
- [ ] Package version in `Payjoin.csproj` carries the intended C# version
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

CI is the publish path. A tag push builds, packs, smoke-tests, and pushes the
package to nuget.org via [trusted publishing] (OIDC) — no long-lived API key
is ever stored. The workflow is
[`.github/workflows/csharp.yml`](../../.github/workflows/csharp.yml) (jobs
`publish-nuget` and `github-release`).

1. Work through the release readiness checklist above on the release commit in
   `master`; confirm every `Build and Test CSharp` job is green.
2. Tag that commit `payjoin-csharp-<version>`, where `<version>` is the
   `Payjoin.csproj` `<Version>` exactly, build metadata included. NuGet
   strips the metadata from the `Payjoin.<version>.nupkg` filename, so
   the publish job strips it from the tag as well before comparing. The
   tag must be annotated and signed by a maintainer key in
   `contrib/release/keys/`, and the tagged commit must be on `master`;
   `verify-tag` refuses to publish otherwise.

   ```shell
   git tag -s payjoin-csharp-0.1.0+payjoin-1.0.0 -m payjoin-csharp-0.1.0+payjoin-1.0.0
   git push upstream payjoin-csharp-0.1.0+payjoin-1.0.0
   ```

   The tag reruns the full build/pack/smoke graph at the tagged commit, then
   `publish-nuget` verifies the tag matches the packed
   `Payjoin.<version>.nupkg`, attests build provenance, exchanges the GitHub
   OIDC token for a short-lived nuget.org key via [`NuGet/login`], and pushes.
   The job runs in the `release` environment: if it has required
   reviewers, approve the paused run before anything reaches nuget.org.

3. `github-release` attaches the `.nupkg` and a generated `SHA256SUMS` to the
   tag's GitHub release. Optionally sign `SHA256SUMS` locally and upload
   `SHA256SUMS.asc` — never place a GPG key on a runner.
4. Complete the post-publish verification section of the checklist, and verify
   the attestation:
   `gh attestation verify Payjoin.<version>.nupkg -R payjoin/rust-payjoin`.

[trusted publishing]: https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing
