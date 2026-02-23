# AGENTS.md

For the full human guide see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md).

Nightly Rust toolchain (`rust-toolchain.toml`) — required for `cargo fmt`
unstable options.

## Tooling

Tools are provided by nix via direnv. Do not install tools globally.
If you need a new tool, add it to the devshell in `flake.nix` so
others can reproduce. rust-analyzer LSP is available for navigation
(go-to-definition, find-references, hover) — prefer it over grepping.

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

## Spec-code mapping

| Spec section            | Code location                                                    |
| ----------------------- | ---------------------------------------------------------------- |
| BIP 77 sender flow      | `payjoin/src/core/send/v2/mod.rs`                                |
| BIP 77 receiver flow    | `payjoin/src/core/receive/v2/mod.rs`                             |
| BIP 77 directory        | `payjoin-directory/src/lib.rs` `handle_decapsulated_request()`   |
| BIP 78 sender checklist | `payjoin/src/core/send/mod.rs` `PsbtContext::process_proposal()` |
| BIP 78 receiver checks  | `payjoin/src/core/receive/mod.rs` `OriginalPayload` methods      |
| OHTTP (RFC 9458)        | `payjoin/src/core/ohttp.rs`                                      |

## Non-obvious things

- `payjoin/src/lib.rs` re-exports all of `src/core/` — the `core`
  module is the entire implementation but is `pub(crate)`.
- `receive::v2` types wrap `receive::common` via `.inner`; all PSBT
  logic lives in `common/`.
- Relay vs directory routing lives in `payjoin-mailroom`, not in
  either sub-crate.
- V1 proposals through V2 directories MUST disable output substitution
  (enforced in `receive::v2::unchecked_from_payload()`).

## AI Disclosure

Add to PR body: `Disclosure: co-authored by <agent-name>`

Do **not** add `Co-Authored-By` in commits.
