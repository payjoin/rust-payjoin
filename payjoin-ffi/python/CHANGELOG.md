## [0.20.0]

#### APIs added

- Make backwards-compatible `v2` to `v1` sends possible.

#### APIs changed

- Removed `contribute_non_nitness_input` from `v1` & `v2`.
- Allow receivers to make `payjoins` out of sweep transactions ([#259](https://github.com/payjoin/rust-payjoin/pull/259)).
- Encode &ohttp= and &exp= parameters in the &pj= URL as a fragment instead of as URI params ([#298](https://github.com/payjoin/rust-payjoin/pull/298))

## [0.18.0]

This release updates the python library to `payjoin` version `0.18.0`.

### Features & Modules

#### Send module

- ##### V1
  - `RequestBuilder` exposes `from_psbt_and_uri`, `build_with_additional_fee`, `build_recommended`, `build_non_incentivizing`,
    `always_disable_output_substitution`.
  - `RequestContext` exposes `extract_contextV1` & `extract_contextV2`.
  - `ContextV1` exposes `process_response`.
- ##### V2
  - `ContextV2` exposes `process_response`.

#### Receive module

- ##### V1
  - `UncheckedProposal` exposes `from_request`, `extract_tx_to_schedule_broadcast`, `check_broadcast_suitability`, `build_non_incentivizing`,
    `assume_interactive_receiver` & `always_disable_output_substitution`.
  - `MaybeInputsOwned` exposes `check_inputs_not_owned`.
  - `MaybeMixedInputScripts` exposes `check_no_mixed_input_scripts`.
  - `MaybeInputsSeen` exposes `check_no_inputs_seen_before`.
  - `OutputsUnknown` exposes `identify_receiver_outputs`.
  - `ProvisionalProposal` exposes `try_substitute_receiver_output`, `contribute_non_witness_input`, `contribute_witness_input`, `try_preserving_privacy` &
    `finalize_proposal`.
  - `PayjoinProposal` exposes `is_output_substitution_disabled`, `owned_vouts`, `psbt` & `utxos_to_be_locked`.
- ##### V2
  - `SessionInitializer` exposes `from_directory_config`, `process_res` & `extract_request`.
  - `ActiveSession` exposes `extract_request`, `process_res`, `pj_uri_builder` & `pj_url`.
  - `V2UncheckedProposal` exposes `extract_tx_to_schedule_broadcast`, `check_broadcast_suitability` & `assume_interactive_receiver`.
  - `V2MaybeInputsOwned` exposes `check_inputs_not_owned`.
  - `V2MaybeMixedInputScripts` exposes `check_no_mixed_input_scripts`.
  - `V2MaybeInputsSeen` exposes `check_no_inputs_seen_before`.
  - `V2OutputsUnknown` exposes `identify_receiver_outputs`.
  - `V2ProvisionalProposal` exposes `try_substitute_receiver_output`, `contribute_non_witness_input`, `contribute_witness_input`, `try_preserving_privacy` &
    `finalize_proposal`.
  - `V2PayjoinProposal` exposes `process_res`, `extract_v1_req`, `extract_v2_req`, `is_output_substitution_disabled`, `owned_vouts`, `psbt` &
    `utxos_to_be_locked`.

#### io module

- Exposed `fetch_ohttp_keys()` to fetch the `ohttp` keys from the specified `payjoin` directory.
