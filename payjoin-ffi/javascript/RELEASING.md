# Releasing the payjoin npm package

Maintainer documentation for publishing the `payjoin` package to
[npmjs.com](https://www.npmjs.com/package/payjoin). Consumer documentation
lives in [`README.md`](README.md).

## Versioning

- The package version is set in `package.json`.
- It is the package's own semantic version, independent of the
  `payjoin-ffi` crate version. The language bindings follow a
  `{version}+payjoin-{version}` convention where the build metadata
  names the wrapped payjoin core release, but npm strips build metadata
  from published versions, so `package.json` carries the bare version
  and records the full one in a `releaseTag` field for traceability.
  The release tag carries the full version too. Keep `releaseTag` in
  sync when bumping the version.
- A release that only changes the wrapped payjoin core version still
  needs at least a patch bump: npm sees only the bare version and
  rejects republishing one that already exists.
- `package.json` is the only place the version is maintained: the publish
  job derives the version from the packed tarball and refuses to publish
  if it does not match the pushed tag.

## Publishing

CI is the publish path. On every pull request touching `payjoin-ffi/**`,
the `Build and Test JavaScript` workflow builds the wasm package, packs the
tarball with [`contrib/pack.sh`](contrib/pack.sh), and smoke-installs it on
Linux and macOS. The tarball ships only `dist/` (wasm + compiled
TypeScript), which is platform-independent.

1. Confirm every `Build and Test JavaScript` job is green on the release
   commit in `master`.
2. Tag that commit `payjoin-javascript-<version>`, where `<version>` is the
   `package.json` `releaseTag` value exactly; the publish job strips the
   build metadata before comparing the tag against the packed tarball.
   The tag must be annotated and signed by a maintainer key in
   `contrib/release/keys/`, and the tagged commit must be on `master`;
   `verify-tag` refuses to publish otherwise.

    ```shell
    git tag -s payjoin-javascript-0.2.0+payjoin-1.0.0 -m payjoin-javascript-0.2.0+payjoin-1.0.0
    git push upstream payjoin-javascript-0.2.0+payjoin-1.0.0
    ```

    The tag reruns the full build/pack/smoke graph at the tagged commit,
    then `publish-npm` verifies the tag matches the packed tarball, attests
    build provenance, and publishes through npm
    [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC),
    so no long-lived token is stored anywhere. The job runs in the `release`
    environment: approve the paused run before anything reaches the
    registry.

3. `github-release` attaches the tarball and a generated `SHA256SUMS` to
   the tag's GitHub release. Optionally sign `SHA256SUMS` locally and
   upload `SHA256SUMS.asc`.
4. Verify the publication: the npmjs.com listing shows the new version
   with a provenance badge, and
   `gh attestation verify payjoin-<version>.tgz -R payjoin/rust-payjoin`
   passes against the release asset.
