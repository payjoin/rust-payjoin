## [0.23.0]

- Update to payjoin-0.23.0
- Expose many error variants
  ([#58](https://github.com/LtbLightning/payjoin-ffi/pull/58))
  ([#71](https://github.com/LtbLightning/payjoin-ffi/pull/71))
- Bind payjoin-test-utils ([#82](https://github.com/LtbLightning/payjoin-ffi/pull/82))
- Depend on bitcoin-ffi @ 6b1d1315dff8696b5ffeb3e5669f308ade227749
- Rename to payjoin-ffi from payjoin_ffi to match bitcoin-ffi

## [0.22.1]
- Expose label and message params on Uri. ([#44](https://github.com/LtbLightning/payjoin-ffi/pull/44))

## [0.22.0]
- Update `payjoin` to `0.22.0`. (Serialize reply_key with Sender [#41](https://github.com/LtbLightning/payjoin-ffi/pull/41))

## [0.21.2]
- Add `pj_endpoint` method to `PjUri` types. ([#40](https://github.com/LtbLightning/payjoin-ffi/pull/40))

## [0.21.1]
- Add `to_json` and `from_json` methods to `Sender` and `Receiver` UniFFI types. ([#39](https://github.com/LtbLightning/payjoin-ffi/pull/39))

## [0.21.0]
This release updates the bindings libraries to `payjoin` version `0.21.0`.
#### APIs changed
- Major overhaul to attempt a stable BIP 77 protocol implementation.
- v1 support is now only available through the V2 backwards-compatible APIs.
- see [payjoin-0.21.0 changelog](https://github.com/payjoin/rust-payjoin/blob/master/payjoin/CHANGELOG.md#0210) for more details.
- Separate `payjoin_ffi` and `payjoin_ffi::uni` UniFFI types into two layers.

## [0.20.0]
#### APIs added
- Make backwards-compatible `v2` to `v1` sends possible.
#### APIs changed
- Removed `contribute_non_nitness_input`  from `v1` & `v2`.
- Allow receivers to make `payjoins` out of sweep transactions ([#259](https://github.com/payjoin/rust-payjoin/pull/259)).
- Encode &ohttp= and &exp= parameters in the &pj= URL as a fragment instead of as URI params ([#298](https://github.com/payjoin/rust-payjoin/pull/298))

## [0.18.0]
This release updates the bindings libraries to `payjoin` version `0.18.0`.
#### APIs changed
- Upgrade `receive/v2` type state machine to resume multiple `payjoins` simultaneously ([#283](https://github.com/payjoin/rust-payjoin/pull/283))
- Refactor output substitution with new fallable `try_substitute_outputs` ([#277](https://github.com/payjoin/rust-payjoin/pull/277))
- Replaced `Enroller` with `SessionInitializer`.
- Replaced `Enrolled` with `ActiveSession`.
- Replaced `fallback_target()` with `pj_url`.
#### APIs added
- Exposed `PjUriBuilder` and `PjUri`.
- Exposed `pjUrl_builder()` in `ActiveSession`.
- Exposed `check_pj_supported()` in `PjUri`.
- Exposed `fetch_ohttp_keys()` to fetch the `ohttp` keys from the specified `payjoin` directory.

## [0.13.0]
### Features & Modules
#### Send module
- #####  V1
    - `RequestBuilder` exposes `from_psbt_and_uri`, `build_with_additional_fee`, `build_recommended`, `build_non_incentivizing`, `always_disable_output_substitution`.
    - `RequestContext` exposes `extract_contextV1` & `extract_contextV2`.
    - `ContextV1` exposes `process_response`.
- ##### V2
    - `ContextV2` exposes `process_response`.
#### Receive module
- #####  V1
    - `UncheckedProposal` exposes `from_request`, `extract_tx_to_schedule_broadcast`, `check_broadcast_suitability`, `build_non_incentivizing`,
      `assume_interactive_receiver` &`always_disable_output_substitution`.
    - `MaybeInputsOwned` exposes `check_inputs_not_owned`.
    - `MaybeMixedInputScripts` exposes `check_no_mixed_input_scripts`.
    - `MaybeInputsSeen` exposes `check_no_inputs_seen_before`.
    - `OutputsUnknown` exposes `identify_receiver_outputs`.
    - `ProvisionalProposal` exposes `substitute_output_address`, `contribute_non_witness_input`, `contribute_witness_input`, `try_preserving_privacy` &
      `finalize_proposal`.
    - `PayjoinProposal` exposes `is_output_substitution_disabled`, `owned_vouts`, `psbt` & `utxos_to_be_locked`.
- ##### V2
    - `Enroller` exposes `from_directory_config`, `process_response` & `extract_request`.
    - `Enrolled` exposes `extract_request`, `process_response` & `fall_back_target`.
    - `V2UncheckedProposal` exposes  `extract_tx_to_schedule_broadcast`, `check_broadcast_suitability` & `assume_interactive_receiver`.
    - `V2MaybeInputsOwned` exposes `check_inputs_not_owned`.
    - `V2MaybeMixedInputScripts` exposes `check_no_mixed_input_scripts`.
    - `V2MaybeInputsSeen` exposes `check_no_inputs_seen_before`.
    - `V2OutputsUnknown` exposes `identify_receiver_outputs`.
    - `V2ProvisionalProposal` exposes `substitute_output_address`, `contribute_non_witness_input`, `contribute_witness_input`, `try_preserving_privacy` &
      `finalize_proposal`.
    - `V2PayjoinProposal` exposes `deserialize_res`, `extract_v1_req`, `extract_v2_req`, `is_output_substitution_disabled`, `owned_vouts`, `psbt` &
      `utxos_to_be_locked`.
