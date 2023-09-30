# Payjoin Changelog

## 0.10.0

- Export `base64` with feature by @jbesraa in #102
- Improve `receive` api with `ProvisionalProposal`by @jbesraa in #90
- Document `create_pj_request` by @jbesraa in #87
- Add BIP 78 reccommended fee `Configuration` by @DanGould in #86

## 0.9.0

Bumping `bitcoin` and other crates was a breaking api change. This is a 0.8.1 semver re-release.

- Bump `bitcoin-0.30.0`
- Bump `bip21-0.3.1`
- Swap `base64-0.13.0` for `bitcoin`'s `base64` feature export
- Support MSRV 1.57.0

## 0.8.2

- Support MSRV 1.57.0

## 0.8.1 (yanked)

- Bump `bitcoin-0.30.0`
- Bump `bip21-0.3.1`
- Swap `base64-0.13.0` for `bitcoin`'s `base64` feature export

## 0.8.0

- Test receiver compatibility with BlueWallet
- Rename `sender`, `receiver` features `send`, `receive`
- Rename `PayJoin` `Payjoin`
- introduce `receive::Error` for fallable checklist items [#59](https://github.com/payjoin/rust-payjoin/pull/59)
- Display receiver errors, RequestErrors with JSON (https://github.com/payjoin/rust-payjoin/pull/49)

## 0.7.0

- Upgrade receiver to beta quality
- Improve receiver SDK interface
- Smoke test receiver with BTCPayServer, Wasabi, and Samourai
- Add receiver inputs at random index
- Improve and expand log calls
- Apply additional fee contribution without estimating psbt size

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
