# Releasing language bindings

Python, JavaScript, Dart, and C# share the `payjoin-ffi` version. A single
signed tag, `payjoin-ffi-<version>+payjoin-<core-version>`, starts one release workflow for all four
publishers and the Kotlin checks. For the first common release this is
`payjoin-ffi-0.25.0+payjoin-1.2.0`.

## Versions

The FFI Cargo manifest determines the common version. Python and npm
publish it without core metadata. Dart and the C# project retain the core version as
build metadata, and JavaScript records it in `releaseTag`. NuGet strips
that metadata from the package filename.

Prereleases use `-alpha.N`, `-beta.N`, `-rc.N`, or `-preview.N`. Python uses
the corresponding PEP 440 spelling, for example `0.26.0-rc.1` becomes
`0.26.0rc1`; alpha becomes `a`, beta becomes `b`, and preview becomes `rc`.
Choose either rc or preview for a release series because Python treats
them as the same phase. npm prereleases publish to the `next` channel;
stable releases publish to `latest`.

Bump every package together, including when a change affects only one
language or only the wrapped core version. Update both maintained Cargo
lockfiles, the Python lockfile, the npm lockfile, and the changelogs.
Changing only build metadata does not create a new package identity in
all registries. Validate the manifests with:

```shell
nix develop .#release -c python3 contrib/release/bindings-version.py
```

Version 0.25.0 intentionally skips the earlier independent version
sequences. Historical versions and tags remain available. Consumers with
version constraints limited to the old minor must explicitly upgrade.

## Registry configuration

Before the first shared tag, configure pub.dev automated publishing with
repository `payjoin/rust-payjoin`, tag pattern `payjoin-ffi-{{version}}`,
and environment `release`. See the [pub.dev instructions]. Check that
GitHub tag rules and the release environment allow the new tag prefix.

Configure the PyPI, npm, and NuGet trusted publishers to use workflow
`bindings-release.yml` and environment `release`, keeping the existing
repository and package identities. Publication has moved out of the
individual language workflows. Complete these settings before pushing
the first shared tag.
Kotlin has checks only, and this tag does not publish the FFI Rust crate.

## Publishing

1. Merge the version bump and confirm all binding checks pass on master.
2. Create the single signed tag using a key in `contrib/release/keys/`:

   ```shell
   nix develop .#release -c contrib/release/tag.sh payjoin-ffi
   ```

   The script checks version consistency and master ancestry. Its
   `--bindings` option also selects this single tag, alongside any pending
   Rust crate tags. Individual language selectors are no longer accepted.

3. Push the exact tag printed by the script. The single `Release language
bindings` run verifies the signed tag and waits for every language's
   build and package checks, including Kotlin. Dart stages its package
   with native Rust source pinned to the tagged commit. PRs validate its
   package against the workspace so a core bump can be checked before core
   publication.
4. Approve the one `publish` job in the `release` environment. This single
   approval starts publication to PyPI, npm, NuGet, and pub.dev with OIDC.
   The job downloads the tested packages and publishes them sequentially.
   Keep required reviewers configured on this environment.
5. Verify installation of the new version from all four registries and
   inspect the release workflow results. Python wheels, the npm tarball,
   the NuGet package, and the staged Dart archive are attached to the same
   GitHub release. One `SHA256SUMS` covers every asset and the native
   libraries inside the NuGet package. Verify provenance using
   `gh attestation verify FILE -R payjoin/rust-payjoin` for the wheels,
   npm tarball, and NuGet package. Optionally sign `SHA256SUMS` locally
   and upload `SHA256SUMS.asc`.

## Partial failures

Publication across registries is sequential and cannot be rolled back.
If publication fails after a registry accepted its package, verify that
version and its provenance before continuing. Start `bindings-release.yml`
with **Run workflow**, select the same signed tag as its ref, and enable
only the recovery switches for languages already published successfully.
Enter the original release run ID as `artifact-run-id`. The workflow
verifies that run belongs to the same release workflow and tagged commit,
and reuses its tested archives for publication and the GitHub release.
The recovery run checks every language again and still requires
one release approval. The switches default to false and are unavailable
on tag pushes. Do not use them for a language that has not been published.
If no registry accepted a package, retry the failed job normally.

Retry only the asset job if publication succeeded and attaching assets
failed. Never move a published tag or replace a published package;
corrections require another common version.

[pub.dev instructions]: https://dart.dev/tools/pub/automated-publishing
