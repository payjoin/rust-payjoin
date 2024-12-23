# Payjoin Changelog

## 0.22.0

- Propagate Uri Fragment parameter errors to the caller
- Have `Sender` to persist reply key so resumption listens where a previous sender left off

## 0.21.0

- Upgrade rustls v0.22.4
- Depend on [bitcoin-ohttp](https://docs.rs/bitcoin-ohttp/latest/bitcoin_ohttp/)
- Allow receiver to contribute multiple inputs and outputs
- Remove `contribute_witness_inputs` and `contribute_non_witness_inputs` in favor of a single consolidated `contribute_inputs` function
- Make `InputPair` public to facilitate working with inputs in coin selection and input contributions
- Enable receiver fee contributions in `apply_fee`, which now requires a max_feerate parameter
- Fix weight estimations for nested segwit inputs
- Fix mixed input scripts receiver check in Payjoin V1 to only error if the receiver would *introduce* mixed types
- Allow mixed input scripts in Payjoin V2
- Implement client end-to-end encryption using HPKE using [bitcoin-hpke](https://docs.rs/bitcoin-hpke/latest/bitcoin_hpke/)
- Make session initialization implicit
- Make payloads uniform by removing sender auth key
- Shorten subdirectory IDs to 64 pseudorandom bits [#386](https://github.com/payjoin/rust-payjoin/pull/386)
- Clarify send and receive module documentation [#407](https://github.com/payjoin/rust-payjoin/pull/407)
- Pad ohttp messages to consistent 8192 bytes [#395](https://github.com/payjoin/rust-payjoin/pull/395)
- encode subdirectory IDs in bech32 and other QR optimizations [#417](https://github.com/payjoin/rust-payjoin/pull/417)
- Upgrade to bitcoin v0.32.5
- Work around '#' escaping bug in bip21 crate [#373](https://github.com/payjoin/rust-payjoin/pull/373)
- Hide `_danger-local-https` feature behind `_` prefix so it doesn't show up in docs [#423](https://github.com/payjoin/rust-payjoin/pull/423)


## 0.20.0

- remove `contribute_non_witness_input` because it was unused
- Fix output checks
- Make backwards-compatible v2 to v1 sends possible
- Bump bitcoin to v0.32.2

## 0.19.0

This release attempts to stabilize the Payjoin V2 Bitcoin URI format. That includes placing v2-specific parameters in the URI's pj parameter's fragment and including the `exp` expiration parameter.

- Error if send or receive session expires with `exp` parameter [#299](https://github.com/payjoin/rust-payjoin/pull/299)
- Encode `&ohttp=` and `&exp=` parameters in the `&pj=` URL as a fragment instead of as URI params [#298](https://github.com/payjoin/rust-payjoin/pull/298)
- Allow receivers to make payjoins out of sweep transactions [#259](https://github.com/payjoin/rust-payjoin/pull/259)
- Fix: Correctly set v=2 query parameter for v2 senders [#320](https://github.com/payjoin/rust-payjoin/pull/320)

### Contributors:

@DanGould, @spacebear21, @BitcoinZavior

## 0.18.0

- Handle OHTTP encapsulated response status ([#284](https://github.com/payjoin/rust-payjoin/pull/284))
- Upgrade `receive::v2` Typestate machine to resume multiple payjoins simultaneously ([#283](https://github.com/payjoin/rust-payjoin/pull/283))
    - `Enroller` became `SessionInitializer`
    - `Enrolled` became `ActiveSession`
        - `fallback_target()` became `pj_url()`
        - `pj_url_builder()` was introduced
    - `ContextV2` became `SessionContext`
        - Include a bitcoin address in `SessionContext`
    - Document it all ([#308](https://github.com/payjoin/rust-payjoin/pull/308))
- `send::ResponseError` variants fields got explicit names ([#304](https://github.com/payjoin/rust-payjoin/pull/304))
- Refactor output substitution with new fallable `try_substitute_outputs` ([#277](https://github.com/payjoin/rust-payjoin/pull/277))

### Contributors:

@DanGould, @grizznaut, @jbesraa, @thebrandonlucas

## 0.17.0

- Prepare Payjoin PSBT with no output keypaths ([#270](https://github.com/payjoin/rust-payjoin/pull/270))
- Restore sender UTXOs before Payjoin Signing ([#280](https://github.com/payjoin/rust-payjoin/pull/280))
- Deserialize url::Url with url/serde feature instead of custom deserializer ([#286](https://github.com/payjoin/rust-payjoin/pull/286))

## 0.16.0

- `io` feature introduced to fetch `OhttpKeys`. This feature will include optional networking supplied by reqwest.
- `V1_REQ_CONTENT_TYPE`, `V2_REQ_CONTENT_TYPE` request headers included
- `bitcoind/rand` transitive dependency from `secp256k/rand` used for randomness instead of `rand`
- Sender input signatures removed before processing payjoin PSBT in the receiver
- `ProvisionalProposal::is_output_substitution_disabled` is exposed
- `Request` types are consolidated into a single type
- Remove `Enrolled::pubkey()`
- `send::Error::V2` replaced with specific HPKE and OhttpEncapsulation error variants
- HPKE out of bounds errors fixed
- Disable output substitution from V1 sender as V2 receiver

## 0.15.0

### API

- Introduce OhttpKeys type (#194)
- Ser/de Enrolled with serde
- Expose only public receive::Error (#201)
- Name payjoin-directory and OHTTP relay according to BIP 77 (#203)

### Fixes

- Encode ohttp_keys in Uri without padding (#214)

## 0.14.0

### API

- Handle `supported` versions in `ResponseError`
- Make `RequestContext`, `RequestBuilder` `Clone`
- Expose v2 mod internally to `pub(crate)` only
- Use typesafe KeyConfig for ohttp d/encapsulation 
- Use spec OHTTP media types
- Build PjUri with PjUriBuilder (#185)
- Parse and pass urls as `Url` instead of `String`

### Fixes

- Remove broken doctests from send and receive mods (#179)

## 0.13.0

### API

- Parse json errors from the receiver into `WellKnown` or other `ResponseErrors`

### Fixes

- Fixed problem where outdated OHTTP Config issue was unclear (#153)
- Support Taproot PSBT field clearing and validation (#157)
- Build `v2` docs

## 0.12.0

- Introduce `v2` feature with oblivious, asynchronous, serverless payjoin
- Return `RequestContext` from which either v1 or v2 `(Request, Context)` tuples may be extracted
- Derive `Debug, Clone` from `send::Request`, `receive::UncheckedProposal`, `optional_parameters::Params`
- Don't derive `Debug, Clone` from `uri::{Payjoin, PayjoinParams}`
- Derive `Serialize, Deserialize` for `RequestContext` and `Enrolled` in `v2` to enable persistent state for asynchronous requests
- `UncheckedProposal::check_can_broadcast` became `::check_broadcast_suitability` allowing receiver to specify minnimum acceptable feerate

## 0.11.0

- Introduce `send` `RequestBuilder` flow

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
