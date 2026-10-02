---
name: Minor Release
about: Checklist for releasing a new minor version of a release crate
title: Release CRATE-MAJOR.MINOR+1.0
labels: ""
assignees: ""
---

## Release CRATE MAJOR.MINOR+1.0

Release-managed crates are `payjoin`, `payjoin-cli` and `payjoin-mailroom`. Versions follow
[Semantic Versioning]. Tags are `<crate>-<version>`. The changelog for this release is the
`## Unreleased` section of `CRATE/CHANGELOG.md`; it was written by the pull requests that
landed since the last release, so there is nothing to compile here.

### Summary

<!-- two or three sentences for the announcement -->

### Checklist

#### Bump

- [ ] Branch `bump-CRATE-MAJOR-MINOR+1` from `master`.
- [ ] Set `version` in `CRATE/Cargo.toml` to `MAJOR.MINOR+1.0` and update every workspace
      member's version requirement on it to match.
- [ ] Rename `## Unreleased` in `CRATE/CHANGELOG.md` to `## MAJOR.MINOR+1.0` and add a fresh
      empty `## Unreleased` above it. Read the section once; fix wording, do not add history.
- [ ] Run `contrib/update-lock-files.sh`.
- [ ] One commit, "Bump CRATE version to MAJOR.MINOR+1.0". Open the PR against `master`.
      The `Check release version bump` job runs check-invariants, a publish dry run and,
      for `payjoin`, cargo-semver-checks.
- [ ] Merge.

If a fix must land before the tag, merge it to `master` as usual; it carries its own
changelog line. The bump PR is not edited for it.

#### Tag and publish

- [ ] Check out the merged `master` commit. Run
      `nix develop .#release -c contrib/release/tag.sh CRATE`. It checks the tree is clean
      and on payjoin/rust-payjoin's `master` (fetched by URL, so any remote layout works),
      runs check-invariants, and creates the signed tag `CRATE-MAJOR.MINOR+1.0` with a key
      from `contrib/release/keys/`.
- [ ] Push the tag with the command the script prints.
- [ ] Approve the `release` environment when the workflow asks. Publication, the GitHub
      release and the crates.io/docs.rs verification run from there.

#### After a `payjoin` release

- [ ] Open the bindings bump PR (python, javascript, csharp, dart manifests and changelogs;
      Dart's `native/Cargo.toml` pins the `payjoin-MAJOR.MINOR+1.0` tag commit, never a
      branch commit). Merge, then run
      `nix develop .#release -c contrib/release/tag.sh --bindings` and push the tags.
- [ ] Bump dependent release crates (`payjoin-cli`, `payjoin-mailroom`) on their own
      schedule, each with this checklist. Their tags verify that `payjoin` is already on
      crates.io.

#### Announce

- [ ] Discord, Twitter, Nostr, stacker.news, using the Summary.

[Semantic Versioning]: https://semver.org/
