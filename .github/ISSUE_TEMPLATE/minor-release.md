---
name: Minor Release
about: Checklist for releasing a new minor version bump
title: Release MAJOR.MINOR+1.0
labels: ""
assignees: ""
---

## Create a new minor release

### Summary

<--release summary to be used in announcements-->

### Commit

<--latest commit ID to include in this release-->

### Changelog

<--add notices from PRs merged since the prior release, see ["keep a changelog"]-->

### Checklist

Release numbering must follow [Semantic Versioning]. These steps assume the current `master`
branch **development** version is _MAJOR.MINOR.0_.

#### On the day of the feature freeze

Change the `master` branch to the next MINOR+1 version:

- [ ] Switch to the `master` branch.
- [ ] Create a new PR branch called `bump-CRATE-MAJOR-MINOR+1`, eg. `bump-CRATE-0-22`.
- [ ] Bump the `bump-CRATE-MAJOR-MINOR+1` branch to the next development MINOR+1 version.
  - Change the `Cargo.toml` version value to `MAJOR.MINOR+1.0` for all crates in the workspace.
  - Run `contrib/update-lock-files.sh ` to apply upgrades to the Cargo lock files.
  - Update the `CHANGELOG.md` file.
  - The commit message should be "Bump CRATE version to MAJOR.MINOR+1.0".
- [ ] Create PR for the `bump-CRATE-MAJOR-MINOR+1` branch to `master`.
  - Title PR "Bump CRATE version to MAJOR.MINOR+1.0".
- [ ] Merge the `bump-CRATE-MAJOR-MINOR+1` branch to `master`.

If any issues need to be fixed before the _MAJOR.MINOR+1.0_ version is released:

- [ ] Merge fix PRs to the `master` branch.
- [ ] Git cherry-pick fix commits to the `bump-CRATE-MAJOR.MINOR+1` branch.
- [ ] Verify fixes in `bump-CRATE-MAJOR.MINOR+1` branch.

#### On the day of the release

Tag and publish new release:

- [ ] Add a tag to the `HEAD` commit in the `master` branch.
  - The tag name should be `CRATE-MAJOR.MINOR+1.0`
  - The first line of the tag message should be "Release CRATE-MAJOR.MINOR+1.0".
  - In the body of the tag message put a copy of the **Summary** and **Changelog** for the release.
  - Make sure the tag is signed, for extra safety use the explicit `--sign` flag.
- [ ] Wait for the CI to finish one last time.
- [ ] Build the docs locally to ensure they are building correctly.
- [ ] Push the new tag to the `payjoin/rust-payjoin` repo.
- [ ] Publish the crate in question crates to crates.io.
- [ ] Create the release on GitHub.
  - Go to "tags", click on the dots on the right and select "Create Release".
  - Set the title to `Release CRATE-MAJOR.MINOR+1.0`.
  - In the release notes body put the **Summary** and **Changelog**.
  - Use the "+ Auto-generate release notes" button to add details from included PRs.
  - Until we reach a `1.0.0` release check the "Pre-release" box.
- [ ] Make sure the new release shows up on [crates.io] and that the docs are built correctly on [docs.rs].
- [ ] Announce the release, using the **Summary**, on Discord, Twitter, Nostr, and stacker.news.
- [ ] Celebrate 🎉

[Semantic Versioning]: https://semver.org/
["keep a changelog"]: https://keepachangelog.com/en/1.0.0/
