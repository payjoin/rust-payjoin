---
name: Minor Release
about: Checklist for releasing a new minor version bump
title: Release MAJOR.MINOR+1.0
labels: ""
assignees: ""
---

## Create a new minor release

### Summary

<!-- release summary to be used in announcements -->

### Commit

<!-- latest commit ID to include in this release -->

### Changelog

<!-- add notices from PRs merged since the prior release, see ["keep a changelog"] -->

### Checklist

Release numbering must follow [Semantic Versioning]. These steps assume the current `master`
branch **development** version is _MAJOR.MINOR.0_. Release-managed crates are `payjoin`,
`payjoin-cli`, and `payjoin-mailroom`; tags use the `<crate>-<version>` scheme.

#### On the day of the feature freeze

Change the `master` branch to the next MINOR+1 version:

- [ ] Switch to the `master` branch.
- [ ] Create a new PR branch called `bump-CRATE-MAJOR-MINOR+1`, eg. `bump-CRATE-0-22`.
- [ ] Bump the `bump-CRATE-MAJOR-MINOR+1` branch to the next development MINOR+1 version.
  - Change the `Cargo.toml` version value to `MAJOR.MINOR+1.0` for the crate being released,
    and update every workspace member's version requirement on it to match.
  - Run `contrib/update-lock-files.sh` to apply upgrades to the Cargo lock files.
  - Update the crate's `CHANGELOG.md` file, adding a `## MAJOR.MINOR+1.0` section that
    summarizes the PRs merged since the last release tag.
  - The commit message should be "Bump CRATE version to MAJOR.MINOR+1.0".
- [ ] Create PR for the `bump-CRATE-MAJOR-MINOR+1` branch to `master`.
  - Title PR "Bump CRATE version to MAJOR.MINOR+1.0".
- [ ] Merge the `bump-CRATE-MAJOR-MINOR+1` branch to `master`.

If any issues need to be fixed before the _MAJOR.MINOR+1.0_ version is released:

- [ ] Merge fix PRs to the `master` branch.
- [ ] Git cherry-pick fix commits to the `bump-CRATE-MAJOR.MINOR+1` branch.
- [ ] Verify fixes in `bump-CRATE-MAJOR.MINOR+1` branch.

#### On the day of the release

- [ ] Create a signed annotated tag on the `HEAD` commit in the `master` branch.
  - The tag name should be `CRATE-MAJOR.MINOR+1.0`, eg. `payjoin-1.0.0`.
  - The first line of the tag message should be "Release CRATE-MAJOR.MINOR+1.0".
  - In the body of the tag message put a copy of the **Summary** and **Changelog** for the release.
  - Sign with a key committed under `contrib/release/keys/`, using the explicit `--sign` flag.
- [ ] Push the new tag to the `payjoin/rust-payjoin` repo.
- [ ] Approve the `release` environment when it requests a reviewer.
- [ ] Announce the release, using the **Summary**, on Discord, Twitter, Nostr, and stacker.news.
- [ ] Celebrate 🎉

[Semantic Versioning]: https://semver.org/
["keep a changelog"]: https://keepachangelog.com/en/1.0.0/
