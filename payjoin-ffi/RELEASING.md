# Releasing the language bindings

Python, JavaScript, C#, and Dart share the `payjoin-ffi` version and are
released together from one signed tag, `payjoin-ffi-<version>`. The
first shared release is `payjoin-ffi-0.25.0`. Kotlin has no published
package yet; the tag only runs its checks. The `payjoin-ffi` crate itself
is not published to crates.io.

## Versions

`payjoin-ffi/Cargo.toml` holds the shared version. Each package manifest
repeats it:

| Manifest                  | Carries                   |
| ------------------------- | ------------------------- |
| `python/pyproject.toml`   | version, PEP 440 spelling |
| `javascript/package.json` | `version`                 |
| `dart/pubspec.yaml`       | `version`                 |
| `csharp/Payjoin.csproj`   | `Version`                 |

Pre-releases are `-rc.N` only; Python spells `0.26.0-rc.1` as `0.26.0rc1`,
and npm publishes pre-releases to the `next` dist-tag. The wrapped
`payjoin` release is not part of the version; the changelog entry names
it, and `payjoin-ffi/Cargo.toml` requires exactly that version. Every
release bumps the version, including one that only changes the wrapped
core.

Prepare the bump PR with:

```shell
nix develop .#release -c contrib/release/bump.sh --no-lock payjoin-ffi X.Y.Z
```

It sets the version in `payjoin-ffi/Cargo.toml`, the four package
manifests, `python/uv.lock` and `javascript/package-lock.json`, renames
`## Unreleased` in `payjoin-ffi/CHANGELOG.md` to the version with a fresh
empty `## Unreleased` above it and a first entry naming the wrapped
`payjoin` release, and opens a section in each language changelog with a
stock entry pointing at it. The lock file step calls
`cargo +nightly`, which the release shell lacks, so pass `--no-lock`
there, then run `contrib/update-lock-files.sh` from a rustup shell and
`contrib/release/check-invariants.sh payjoin-ffi` again.

`payjoin-ffi/CHANGELOG.md` is the canonical changelog and becomes the
GitHub release body; pull requests write to its `## Unreleased` section
as they do for the release crates. The language changelogs record only
language-specific changes and link to it; pub.dev displays Dart's. Check
the manifests agree with:

```shell
nix develop .#release -c contrib/release/bindings-version.sh
```

## Registry configuration

Before the first shared tag, point each trusted publisher at the new
workflow, keeping the existing package identities: PyPI, npm, and NuGet
use workflow `bindings-release.yml` and environment `release`; pub.dev
[automated publishing] uses tag pattern `payjoin-ffi-{{version}}` and
environment `release`. Keep required reviewers on the `release`
environment, and allow `payjoin-ffi-*` in the repository's tag rules.

## Publishing

1. Publish the wrapped `payjoin` release first. Dart consumers build the
   bindings from source against it on crates.io.
2. Merge the bump PR and confirm every binding workflow is green on master.
3. Create the signed tag with a key in `contrib/release/keys/`:

   ```shell
   nix develop .#release -c contrib/release/tag.sh payjoin-ffi
   ```

   The script checks that the manifests agree, that the lockfiles and
   changelog match, that the core is published, and that HEAD is on
   master. `tag.sh --bindings` selects the same tag alongside any pending
   crate tags. Push the tag it prints.

4. The `Release language bindings` run verifies the tag, builds and smoke
   tests every language, then pauses four publish jobs on the `release`
   environment. Approve the pending deployment once; it covers all four
   jobs. Each registry is published with OIDC from the tested artifacts.
5. The run attaches the wheels, npm tarball, NuGet package, staged Dart
   package, and one `SHA256SUMS` covering them all, including the native
   libraries inside the NuGet package, to the GitHub release. Verify an
   install from each registry and check provenance with
   `gh attestation verify FILE -R payjoin/rust-payjoin`. Optionally sign
   `SHA256SUMS` locally and upload `SHA256SUMS.asc`; no signing key reaches
   a runner.

## If a publish job fails

Each registry has its own job, so use **Re-run failed jobs** on the same
run and approve the environment again. The re-run publishes from the same
tested artifacts and leaves the registries that already succeeded alone.
Never move a published tag or replace a published package; fix forward
with a new version.

[automated publishing]: https://dart.dev/tools/pub/automated-publishing
