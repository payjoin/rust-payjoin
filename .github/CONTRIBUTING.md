# Contributing

---

Welcome to Payjoin Dev Kit (PDK).

This monorepo is home to the most widely-adopted Payjoin software.

As such, contributions are greatly valued, necessary, and impactful: whether it's reporting issues, writing documentation, or contributing code, we'd love your help!

---

## Communication Channels

Most discussion about Payjoin research and development happens on [Discord](https://discord.gg/6rJD9R684h), or in Github [issues](https://github.com/payjoin/rust-payjoin/issues) or [pull requests](https://github.com/payjoin/rust-payjoin/pulls).

---

## Scope

Issues and pull requests are for technical substance. Foundation
governance, personnel, and licensing or IP matters are out of scope. Take
them to [Foundation leadership](https://payjoin.org/blog/2025/08/08/announcing-payjoin-foundation/)
directly at [admin@payjoin.org](mailto:admin@payjoin.org). Maintainers may lock or hide
off-topic threads by pointing to this section, and may temporarily block
accounts for sustained off-topic participation, with notice.

---

## Issues

Using and testing Payjoin Dev Kit is an effective way for new contributors to both learn and provide value. If you find a bug, incorrect or unclear documentation, or have any other problem, consider [creating an issue](https://github.com/payjoin/rust-payjoin/issues). Before doing so, please search through [existing issues](https://github.com/payjoin/rust-payjoin/issues) to see if your problem has already been addressed or is actively being discussed. If you can, provide a fully reproducible example or the steps we can use to reproduce the issue to speed up the debugging process.

---

## Security

Do not open public issues or pull requests for vulnerabilities. Report them
privately to [security@payjoin.org](mailto:security@payjoin.org) as described
in [SECURITY.md](SECURITY.md).

---

## Documentation

Good documentation is essential to understanding what PDK does and how to use it. Since PDK seeks to raise Payjoin adoption by making it easy for developers to integrate it into their wallets, providing clear and complete documentation is critical. Good documentation is also invaluable to new contributors ramping up quickly. If _you_ find something hard to understand or difficult to figure out how to use from the documentation, it's a sign they could be improved. To contribute to the documentation please [fork the repository](https://github.com/payjoin/rust-payjoin/fork), make changes there, and then submit a pull request.

---

## Code

### Getting Started

If you're looking for somewhere to start contributing code changes, see the [good first issue](https://github.com/payjoin/rust-payjoin/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) list. If you intend to start working on an issue, please leave a comment stating your intent.

If you find a perceived issue like a bug or existing `// TODO` comment, please open an issue first to ensure that the behavior you wish to change can be agreed upon before you sit down to write the fix in earnest.

To contribute a code change:

1. [Fork the repository](https://github.com/payjoin/rust-payjoin/fork).
2. Create a topic branch.
3. Commit changes.

### Commits

The git repository is our source of truth for development history. Therefore the commit history is the most important communication
artifact we produce. Commit messages must follow [the seven rules in this guide by cbeams](https://cbea.ms/git-commit/#seven-rules).

Every commit should be [hygienic](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md#committing-patches) and pass CI. This means tests, linting, and formatting should pass without issues on each commit. Below is a [git hook](https://git-scm.com/book/ms/v2/Customizing-Git-Git-Hooks) you may choose to add to `.git/hooks/pre-commit` in your local repository to perform these checks before each commit:

```sh
#!/usr/bin/env bash
set -euo pipefail

# -------- 1. Rustfmt --------
echo "▶  cargo fmt --check"
cargo fmt --all -- --check

# -------- 2.1 Project-specific linter --------
echo "▶  ./contrib/lint.sh"
./contrib/lint.sh

# -------- 2.2 Documentation builder --------
echo '▶  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --document-private-items'
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --document-private-items

# -------- 3. Fast local test suite --------
echo "▶  ./contrib/test_local.sh"
./contrib/test_local.sh

# -------- 4. lock file verification --------
changed_tomls=$(git diff --cached --name-only --diff-filter=ACMR | grep -E '(^|/)Cargo\.toml$' || true)

if [ -n "$changed_tomls" ]; then
    echo "▶  Checking if lockfiles need updating…"
    ./contrib/update-lock-files.sh
    stale_locks=$(git diff --name-only -- Cargo-minimal.lock Cargo-recent.lock)
    if [ -n "$stale_locks" ]; then
        echo "pre-commit: Cargo.toml changed and lockfiles are stale!"
        echo "Stale lockfiles:"
        echo "$stale_locks"
        echo "Run './contrib/update-lock-files.sh' and stage the lockfiles."
        exit 1
    fi
fi

echo "✓  Pre-commit hook passed"
```

## AI Assistance Notice

> [!IMPORTANT]
>
> If you are using **any kind of AI assistance** to contribute
> it must be disclosed in the pull request.

If you are using any kind of AI assistance while contributing,
**this must be disclosed in the pull request**, along with the extent to
which AI assistance was used (e.g. docs only vs. code generation).
If PR body or comments are being generated by an AI, disclose that as well.
As a small exception, trivial tab-completion doesn't need to be disclosed,
so long as it is limited to single keywords or short phrases.

An example disclosure:

> This PR was written primarily by Claude Code.

Or a more detailed disclosure:

> I consulted ChatGPT to understand the codebase but the solution
> was fully authored manually by myself.

Failure to disclose this is impolite to the human operators
on the other end of the pull request, and it also makes it difficult to
determine how much scrutiny to apply to the contribution.
Please be respectful to maintainers and disclose AI assistance so that
they may help you effectively contribute.

### Nix Development Shells

Where [nix](https://nixos.org/) is available (NixOS or
[otherwise](https://determinate.systems/nix-installer/)), development shells are provided.

The default shell uses rust nightly, and can be activated manually using `nix
develop` in the project root, or automatically with
[direnv](https://determinate.systems/posts/nix-direnv/).

To use the minimal supported version, use `nix develop .#msrv`. `.#stable` is
also provided.

### Testing

We test a few different features combinations in CI. To run all of the combinations locally run `contrib/test.sh`.

If you are adding a new feature please add tests for it.

### Upgrading dependencies

If your change requires a dependency to be upgraded you must please run `contrib/update-lock-files.sh` before submitting any changes.

### Code Formatting

We use the nightly Rust formatter for this project. Please run [`rustfmt`](https://github.com/rust-lang/rustfmt) using the nightly toolchain before submitting any changes.

Non-Rust files are formatted via [Prettier](https://prettier.io/) and other language-specific formatters orchestrated by [`treefmt`](https://github.com/numtide/treefmt). If you modify non-rust code (under `payjoin-ffi/`), run:

```sh
nix fmt
```

### Linting

We use [`clippy`](https://github.com/rust-lang/rust-clippy) for linting. Please run `contrib/lint.sh` using the nightly toolchain before submitting any changes.

---

## Review and Merging

Pull requests are reviewed on technical merit by the repository
maintainers listed in [CODEOWNERS](CODEOWNERS). Protocol wire behavior
follows the BIP process
([BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki),
[BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md)).
Observable behavior not yet pinned down by a BIP may merge, but is not
considered production ready until it is publicly specified. When
maintainers proceed over a significant technical objection, the rationale
is written up publicly.

---

## Licensing

Crates in this workspace are licensed as declared in each crate's
`Cargo.toml`: `MITNFA` for most crates, dual MIT/Apache-2.0 for
`payjoin-ffi`. Relicensing the workspace to dual MIT/Apache-2.0 is in
progress in [#1540](https://github.com/payjoin/rust-payjoin/issues/1540).
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed under the license of the crate it modifies and
dual MIT/Apache-2.0, without any additional terms or conditions.
