# Contributing

---

Welcome to Payjoin Dev Kit (PDK).

This monorepo is home to the most widely-adopted Payjoin software.

As such, contributions are greatly valued, necessary, and impactful: whether it's reporting issues, writing documentation, or contributing code, we'd love your help!

---

## Communication Channels

Most discussion about Payjoin research and development happens on [Discord](https://discord.gg/X8RRV2VS), or in Github [issues](https://github.com/payjoin/rust-payjoin/issues) or [pull requests](https://github.com/payjoin/rust-payjoin/pulls).

---

## Issues

Using and testing Payjoin Dev Kit is an effective way for new contributors to both learn and provide value. If you find a bug, incorrect or unclear documentation, or have any other problem, consider [creating an issue](https://github.com/payjoin/rust-payjoin/issues). Before doing so, please search through [existing issues](https://github.com/payjoin/rust-payjoin/issues) to see if your problem has already been addressed or is actively being discussed. If you can, provide a fully reproducible example or the steps we can use to reproduce the issue to speed up the debugging process.

---

## Documentation

Good documentation is essential to understanding what PDK does and how to use it. Since PDK seeks to raise Payjoin adoption by making it easy for developers to integrate it into their wallets, providing clear and complete documentation is critical. Good documentation is also invaluable to new contributors ramping up quickly. If _you_ find something hard to understand or difficult to figure out how to use from the documentation, it's a sign they could be improved. To contribute to the documentation please [fork the repository](https://github.com/payjoin/rust-payjoin/fork), make changes there, and then submit a pull request.

---

## Code

### Getting Started

If you're looking for somewhere to start contributing code changes, see the [good first issue](https://github.com/payjoin/rust-payjoin/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) list. If you intend to start working on an issue, please leave a comment stating your intent.

To contribute a code change:

1. [Fork the repository](https://github.com/payjoin/rust-payjoin/fork).
2. Create a topic branch.
3. Commit changes.

### Commits

The git repository is our source of truth for development history. Therefore the commit history is the most important communication
artifact we produce. Commit messages must follow [the seven rules in this guide by cbeams](https://cbea.ms/git-commit/#seven-rules).

Every commit should be [hygenic](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md#committing-patches) and pass CI. This means tests, linting, and formatting should pass without issues on each commit. Below is a [git hook](https://git-scm.com/book/ms/v2/Customizing-Git-Git-Hooks) you may choose to add to `.git/hooks/pre-commit` in your local repository to perform these checks before each commit:

```sh
#!/usr/bin/env bash
set -euo pipefail

# -------- 1. Rustfmt (nightly toolchain) --------
echo "▶  cargo +nightly fmt --check"
cargo +nightly fmt --all -- --check

# -------- 2. Project-specific linter --------
echo "▶  ./contrib/lint.sh"
./contrib/lint.sh

# -------- 3. Fast local test suite --------
echo "▶  ./contrib/test_local.sh"
./contrib/test_local.sh

echo "✓  Pre-commit hook passed"
```

### Nix Development Shells

Where [nix](https://nixos.org/) is available (NixOS or
[otherwise](https://determinate.systems/nix-installer/)), development shells are provided.

The default shell uses rust nightly, and can be activated manually using `nix
develop` in the project root, or automatically with
[direnv](https://determinate.systems/posts/nix-direnv/).

To use the minimal supported version, use `nix develop .#msrv`. `.#stable` is
also provided.

### Testing

We test a few different features combinations in CI. To run all of the combinations locally, have Docker running and run `contrib/test.sh`.

If you are adding a new feature please add tests for it.

### Upgrading dependencies

If your change requires a dependency to be upgraded you must please run `contrib/update-lock-files.sh` before submitting any changes.

### Code Formatting

We use the nightly Rust formatter for this project. Please run [`rustfmt`](https://github.com/rust-lang/rustfmt) using the nightly toolchain before submitting any changes.

### Linting

We use [`clippy`](https://github.com/rust-lang/rust-clippy) for linting. Please run `contrib/lint.sh` using the nightly toolchain before submitting any changes.
