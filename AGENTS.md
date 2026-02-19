# AGENTS.md

For the full human guide see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md).

Nightly Rust toolchain (`rust-toolchain.toml`) — required for `cargo fmt`
unstable options.

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
./contrib/test_local.sh            # does NOT include payjoin-mailroom
treefmt --ci                       # prettier, taplo, nixfmt, shellcheck, shfmt
codespell
```

Per-crate scripts: `{crate}/contrib/test.sh`, `{crate}/contrib/lint.sh`.

## Two Lockfiles

CI tests both `Cargo-minimal.lock` and `Cargo-recent.lock`. After any
dependency change:

```sh
bash contrib/update-lock-files.sh
```

## AI Disclosure

Add to PR body: `Disclosure: co-authored by <agent-name>`

Do **not** add `Co-Authored-By` in commits.
