# Releasing the payjoin npm package

Maintainer documentation for publishing the `payjoin` package to
[npmjs.com](https://www.npmjs.com/package/payjoin). Consumer documentation
lives in [`README.md`](README.md).

## Versioning

- The package version is set in `package.json`.
- It is the package's own semantic version, independent of the
  `payjoin-ffi` crate version while the JavaScript API stabilizes.
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
   `package.json` version exactly, and push the tag:

    ```shell
    git tag payjoin-javascript-0.1.1
    git push upstream payjoin-javascript-0.1.1
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
   upload `SHA256SUMS.asc`; never place a GPG key on a runner.
4. Verify the publication: the npmjs.com listing shows the new version
   with a provenance badge, and
   `gh attestation verify payjoin-<version>.tgz -R payjoin/rust-payjoin`
   passes against the release asset.

One-time setup is account and repository configuration, not part of the
per-release flow: the npmjs.com trusted publisher for the `payjoin`
package (GitHub Actions, repository `payjoin/rust-payjoin`, workflow file
`javascript.yml`, environment `release`), and the `release` GitHub
Actions environment with required reviewers.

## Manual fallback

Use only if the CI publish path is unavailable. Requires npm ownership of
the `payjoin` package and an account with two-factor authentication.

```shell
nix develop .#javascript -c ./payjoin-ffi/javascript/contrib/pack.sh
npm publish payjoin-ffi/javascript/artifacts/payjoin-<version>.tgz
```

A manual publish carries no provenance statement; prefer republishing
through CI for anything consumers will install.
