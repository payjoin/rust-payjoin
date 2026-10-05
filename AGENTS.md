# AGENTS.md

For the full human guide see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md).

Nightly Rust toolchain (`rust-toolchain.toml`) — required for `cargo fmt`
unstable options.

## Tooling

Tools are provided by nix via direnv. Do not install tools globally.
If you need a new tool, add it to the devshell in `flake.nix` so
others can reproduce.

## Commit Rules

Every commit must pass CI independently.

Commit messages follow the seven rules:

1. Separate subject from body with a blank line
2. Limit the subject line to 50 characters
3. Capitalize the subject line
4. Do not end the subject line with a period
5. Use the imperative mood in the subject line
6. Wrap the body at 72 characters
7. Use the body to explain what and why vs. how

## Pre-commit Checks (Tiered)

**Fast (every commit):**

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --keep-going --all-features -- -D warnings
codespell
```

**Full (before push):**

```sh
./contrib/lint.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features \
  --document-private-items
./contrib/test_local.sh
nix fmt -- --ci
codespell
```

Per-crate scripts: `{crate}/contrib/test.sh`, `{crate}/contrib/lint.sh`.

## Two Lockfiles

CI tests both `Cargo-minimal.lock` and `Cargo-recent.lock`. After any
dependency change:

```sh
bash contrib/update-lock-files.sh
```

## Code Review

When reviewing changes, compare the branch against `master` commit by
commit. Check for adherence to the guidelines in
`.github/CONTRIBUTING.md`, relevant test coverage, consistency with the
overall codebase, bugs, missed edge cases, unintended side effects, poor
implementation choices, new panics or unwraps in library code,
unintended public API changes, and other general concerns.

## AI Disclosure

Follow the [AI communication policy](.github/CONTRIBUTING.md#ai-communication).

Do **not** add `Co-Authored-By` in commits.
