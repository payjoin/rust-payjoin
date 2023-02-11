# PayJoin Changelog

## 0.6.0

- Complete sender PSBT validation. Sender is now beta-quality.
- New `receiver` alpha feature to request and receive payjoin
- Support receiver output substitution
- Follow receiver checklist with library typestate
- Coin selection to defeat unnecessary input heuristic
- Reference bitcoind payjoin receiver added to `payjoin-client`
- CLI help added in `payjoin-client`

## 0.5.1-alpha

- Format code with `cargo fmt` rustfmt rules from rust-bitcoin [#15](https://github.com/chaincase-app/payjoin/pull/15)
- Lint code with `cargo clippy` [#15](https://github.com/chaincase-app/payjoin/pull/15)
- Pass through sender error data [#14](https://github.com/chaincase-app/payjoin/pull/14)

## 0.5.0-alpha

- Update to bitcoin 0.29.2

## 0.4.0-alpha

Update to bitcoin 0.28.2
