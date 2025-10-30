# Payjoin Changelog

## 1.0.0-rc.1

This release candidate fixes a BIP78 spec compliance bug, and an issue with the BIP77 sender when polling an arbitrary relay via RFC9540.
It also removes a redundant Sender SessionEvent.

- Fix identify_receiver_outputs (#1168)
- Use full_relay_url in sender GET request (#1166)
- Remove `ReceivedProposalPsbt` infavor of session outcome (#1171)

## 1.0.0-rc.0

Introduce monitoring typestates, replyable error handling, and other updates for more robust session lifecycle management.

Selected Improvements:

### Updates to Typestates and Session Event Log Replay

- Receiver Monitor Typestate (#1061)
- Sender closed variant (#1129)
- Rename sender session events (#1125, #1116)
- Remove `PollingForProposal` from session event (#1128)
- Return closed session state during replays (#1136)
- Introduce `SessionEvent::Closed` (#1078)
- Name multi-field SessionEvent variants (#1051)
- Enforce `handle_fatal_reject` type safety (#1058)
- Remove uninitialized session state (#1014)
- Enforce that `SessionHistory` is created internally (#1062)
- Reduce visibility of common recv abstractions (#1109)
- Abstract V2 Sender over SenderContext and remove public Url (#1141)

### Improve Error Handling

- Handle fatal errors in receiver state machine (#1060)
- Update sender `process_res` to parse and process error response (#1114)
- HPKE encrypt error response (#1115)
- Use `HasReplyableErrorTransition` in reply error typestate (#1130)
- Use reply key for replyable errors to v2 senders (#981)
- Improve `receive` error hierarchy (#1031)
- Separate session replay & protocol operation (#1036)

### API and Dependency Refinements

- Depend on `url/serde` with no default features (#1126)
- Use String type instead of Url on Request Struct (#1122)
- Remove the url crate dep from payjoin-test-utils (#1111)
- Remove use of payjoin::Url and url::Url in public methods (#1057)
- Make `payjoin::uri` module public (#1048)
- Replace `psbt_with_fee_contributions` with pub fn (#1120)
- Refactor sender to validate PjParam by version (#901)
- Replace bitcoind with corepc_node (#1041)
- Bump MSRV to 1.85.0 (#957)
- Upgrade testcontainers (#970)

### Build, CI, and Workflow Enhancements

- Run all tests in macOS CI (#1094)
- Use tracing crate instead of log (#1020)
- Add Pull Request Review Template (#967)
- Add bug issue templates (#758, #784)
- Add Feature Request, Good First Issue, and General Issue Templates (#891)
- Enforce new AI Disclosure in PR Checklist (#1012)

### Miscellaneous Cleanups

- Remove redundant fields from `WantsInputs`, `WantsOutputs`, and `WantsFeeRange` events (#1106, #1102, #1092)
- Remove mailbox from receiver session context (#1112)
- Remove extraneous clones and redundant Vec clones in HPKE encrypt functions (#1089, #982, #845)
- Use `expiration` instead of `expiry` (#1087)
- Clarify request construction methods for sender and receiver (#814)

## 0.24.0

Introduce the Session Event Log for Session Replay

Selected Improvements:

### Introduce Granualar event-based session log for replay

- Alter receiver session as_ref assert and persist::Value import for ReceiverToken (#658)
- Add SessionPersister trait (#716)
- Sender generic over typestate (#728)
- Make Receiver generic over its typestate (#719)
- Receiver Session Events (#760)
- Export `InMemoryTestPersister` under `_test-utils` (#761)
- Capture hpke reply key in session event (#762)
- Sender Session Events (#777)
- Replace Persister with SessionPersister for v2 Sender (#789)
- Persistence follow ups (#638)
- Expose fallback tx off receiver session history (#799)
- Sender session history fallback (#805)
- 0.24 name audit (#803, #810)


### Better ergonomics

- Introduce constructors for SegWit input pairs (#712)
- Introduce constructors for legacy input pairs (#753)


### Organize for readability

- Update README title and add logo & badges (#665)
- Move persist sub module to root module (#656)
- Remove rust docs reference to non-existent method (#655)
- Introduce Payjoin version enum (#668)
- Use IntoUrl for ohttp_relay argument (#692)
- Dedupe ImplementationError (#669)
- Clean up re-exports (#746)


### Various Operational improvements

- Randomly pad OHTTP requests (#715)
- Limit response sizes for v1 (#586)


## 0.23.0

- Make features additive [#430](https://github.com/payjoin/rust-payjoin/pull/430) [#466](https://github.com/payjoin/rust-payjoin/pull/466) [#501](https://github.com/payjoin/rust-payjoin/pull/501) [#518](https://github.com/payjoin/rust-payjoin/pull/518) 
- Make receiver errors replyable to the sender [#474](https://github.com/payjoin/rust-payjoin/pull/474) [#506](https://github.com/payjoin/rust-payjoin/pull/506) [#526](https://github.com/payjoin/rust-payjoin/pull/526) [#606](https://github.com/payjoin/rust-payjoin/pull/606) 
- Separate error modules [#482](https://github.com/payjoin/rust-payjoin/pull/482) 
- Introduce "directory" feature module [#502](https://github.com/payjoin/rust-payjoin/pull/502) 
- Expose test helpers via payjoin-test-utils crate [#484](https://github.com/payjoin/rust-payjoin/pull/484) 
- Accommodate updated BIP78 spec [#505](https://github.com/payjoin/rust-payjoin/pull/505) 
- Fallback to first candidate if avoid_uih fails [#533](https://github.com/payjoin/rust-payjoin/pull/533) 
- Use IntoUrl trait instead of Url in function signatures [#520](https://github.com/payjoin/rust-payjoin/pull/520) 
- Don't accept invalid certs even in tests [#550](https://github.com/payjoin/rust-payjoin/pull/550) 
- Introduce experimental multiparty sender behind the "_multiparty" feature flag [#434](https://github.com/payjoin/rust-payjoin/pull/434) 
- Add support for RFC 9540 ohttp-keys fetching and decentralized BIP 77 directory opt-in [#549](https://github.com/payjoin/rust-payjoin/pull/549) [#570](https://github.com/payjoin/rust-payjoin/pull/570) [#587](https://github.com/payjoin/rust-payjoin/pull/587) 
- Fix the `pjos` BIP21 parameter to match the BIP78 spec [#546](https://github.com/payjoin/rust-payjoin/pull/546) 
- Introduce mutation testing [#573](https://github.com/payjoin/rust-payjoin/pull/573) 
- Add first-class persistence abstraction [#552](https://github.com/payjoin/rust-payjoin/pull/552) 
- Add many more tests, reaching [82%](https://coveralls.io/builds/73029930) coverage - up from 60% when coverage reports were introduced.

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
- `UncheckedProposal::check_can_broadcast` became `::check_broadcast_suitability` allowing receiver to specify minimum acceptable feerate

## 0.11.0

- Introduce `send` `RequestBuilder` flow

## 0.10.0

- Export `base64` with feature by @jbesraa in #102
- Improve `receive` api with `ProvisionalProposal`by @jbesraa in #90
- Document `create_pj_request` by @jbesraa in #87
- Add BIP 78 recommended fee `Configuration` by @DanGould in #86

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
