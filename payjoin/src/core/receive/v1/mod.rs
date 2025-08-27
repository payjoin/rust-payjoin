//! Receive BIP 78 Payjoin v1
//!
//! This module contains types and methods used to receive payjoin via BIP78.
//! Usage is pretty simple:
//!
//! 1. Generate a pj_uri [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
//!    using [`build_v1_pj_uri`]
//! 2. Listen for a sender's request on the `pj` endpoint
//! 3. Parse the request using
//!    [`UncheckedProposal::from_request()`]
//! 4. Validate the proposal using the `check` methods to guide you.
//! 5. Assuming the proposal is valid, augment it into a payjoin with the available
//!    `try_preserving_privacy` and `contribute` methods
//! 6. Extract the payjoin PSBT and sign it
//! 7. Respond to the sender's http request with the signed PSBT as payload.
//!
//! The `receive` feature provides all of the check methods, PSBT data manipulation, coin
//! selection, and transport structures to receive payjoin and handle errors in a privacy
//! preserving way.
//!
//! Receiving payjoin entails listening to a secure http endpoint for inbound requests.  The
//! endpoint is displayed in the `pj` parameter of a [bip
//! 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) request URI.
//!
//! [reference implementation](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli)
//!
//! OHTTP Privacy Warning
//! Encapsulated requests whether GET or POST—**must not be retried or reused**.
//! Retransmitting the same ciphertext (including via automatic retries) breaks the unlinkability and privacy guarantees of OHTTP,
//! as it allows the relay to correlate requests by comparing ciphertexts.
//! Note: Even fresh requests may be linkable via metadata (e.g. client IP, request timing),
//! but request reuse makes correlation trivial for the relay.

mod error;
use bitcoin::OutPoint;
pub(crate) use error::InternalRequestError;
pub use error::RequestError;

use super::*;
pub use crate::receive::common::{WantsFeeRange, WantsInputs, WantsOutputs};
use crate::uri::PjParam;
use crate::{IntoUrl, OutputSubstitution, PjParseError, Version};

const SUPPORTED_VERSIONS: &[Version] = &[Version::One];

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub fn build_v1_pj_uri<'a>(
    address: &bitcoin::Address,
    endpoint: impl IntoUrl,
    output_substitution: OutputSubstitution,
) -> Result<crate::uri::PjUri<'a>, PjParseError> {
    let url = endpoint.into_url().map_err(crate::uri::error::InternalPjParseError::IntoUrl)?;
    let pj_param = PjParam::V1(crate::uri::v1::PjParam::parse(url)?);
    let extras = crate::uri::PayjoinExtras { pj_param, output_substitution };
    Ok(bitcoin_uri::Uri::with_extras(address.clone(), extras))
}

impl UncheckedProposal {
    pub fn from_request(
        body: &[u8],
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, ReplyableError> {
        let validated_body = validate_body(headers, body).map_err(ReplyableError::V1)?;

        let base64 = std::str::from_utf8(validated_body).map_err(InternalPayloadError::Utf8)?;

        let (psbt, params) = crate::receive::parse_payload(base64, query, SUPPORTED_VERSIONS)
            .map_err(ReplyableError::Payload)?;

        Ok(UncheckedProposal { original: Original { psbt, params } })
    }
}

/// The original PSBT and the optional parameters received from the sender.
///
/// This is the first typestate after the retrieval of the sender's original proposal in
/// the receiver's workflow. At this stage, the receiver can verify that the original PSBT they have
/// received from the sender is broadcastable to the network in the case of a payjoin failure.
///
/// The recommended usage of this typestate differs based on whether you are implementing an
/// interactive (where the receiver takes manual actions to respond to the
/// payjoin proposal) or a non-interactive (ex. a donation page which automatically generates a new QR code
/// for each visit) payment receiver. For the latter, you should call [`Self::check_broadcast_suitability`] to check
/// that the proposal is actually broadcastable (and, optionally, whether the fee rate is above the
/// minimum limit you have set). These mechanisms protect the receiver against probing attacks, where
/// a malicious sender can repeatedly send proposals to have the non-interactive receiver reveal the UTXOs
/// it owns with the proposals it modifies.
///
/// If you are implementing an interactive payment receiver, then such checks are not necessary, and you
/// can go ahead with calling [`Self::assume_interactive_receiver`] to move on to the next typestate.
#[derive(Debug, Clone)]
pub struct UncheckedProposal {
    original: Original,
}

impl UncheckedProposal {
    /// Checks that the original PSBT in the proposal can be broadcasted.
    ///
    /// If the receiver is a non-interactive payment processor (ex. a donation page which generates
    /// a new QR code for each visit), then it should make sure that the original PSBT is broadcastable
    /// as a fallback mechanism in case the payjoin fails. This validation would be equivalent to
    /// `testmempoolaccept` Bitcoin Core RPC call returning `{"allowed": true,...}`.
    ///
    /// Receiver can optionally set a minimum fee rate which will be enforced on the original PSBT in the proposal.
    /// This can be used to further prevent probing attacks since the attacker would now need to probe the receiver
    /// with transactions which are both broadcastable and pay high fee. Unrelated to the probing attack scenario,
    /// this parameter also makes operating in a high fee environment easier for the receiver.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsOwned, ReplyableError> {
        self.original.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(MaybeInputsOwned { original: self.original })
    }

    /// Moves on to the next typestate without any of the current typestate's validations.
    ///
    /// Use this for interactive payment receivers, where there is no risk of a probing attack since the
    /// receiver needs to manually create payjoin URIs.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        MaybeInputsOwned { original: self.original }
    }
}

/// Typestate to check that the original PSBT has no inputs owned by the receiver.
///
/// At this point, it has been verified that the transaction is broadcastable from previous
/// typestate. The receiver can call [`Self::extract_tx_to_schedule_broadcast`]
/// to extract the signed original PSBT to schedule a fallback in case the Payjoin process fails.
///
/// Call [`Self::check_inputs_not_owned`] to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    pub(crate) original: Original,
}

impl MaybeInputsOwned {
    /// Extracts the original transaction received from the sender.
    ///
    /// Use this for scheduling the broadcast of the original transaction as a fallback
    /// for the payjoin. Note that this function does not make any validation on whether
    /// the transaction is broadcastable; it simply extracts it.
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.original.psbt.clone().extract_tx_unchecked_fee_rate()
    }

    /// Check that the original PSBT has no receiver-owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsSeen, ReplyableError> {
        self.original.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { original: self.original })
    }
}

/// Typestate to check that the original PSBT has no inputs that the receiver has seen before.
///
/// Call [`Self::check_no_inputs_seen_before`] to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    original: Original,
}
impl MaybeInputsSeen {
    /// Check that the receiver has never seen the inputs in the original proposal before.
    ///
    /// This check prevents the following attacks:
    /// 1. Probing attacks, where the sender can use the exact same proposal (or with minimal change)
    ///    to have the receiver reveal their UTXO set by contributing to all proposals with different inputs
    ///    and sending them back to the receiver.
    /// 2. Re-entrant payjoin, where the sender uses the payjoin PSBT of a previous payjoin as the
    ///    original proposal PSBT of the current, new payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<OutputsUnknown, ReplyableError> {
        self.original.check_no_inputs_seen_before(is_known)?;
        Ok(OutputsUnknown { original: self.original })
    }
}

/// Typestate to check that the outputs of the original PSBT actually pay to the receiver.
///
/// The receiver should only accept the original PSBTs from the sender if it actually sends them
/// money.
///
/// Call [`Self::identify_receiver_outputs`] to proceed.
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    original: Original,
}

impl OutputsUnknown {
    /// Validates whether the original PSBT contains outputs which pay to the receiver and only
    /// then proceeds to the next typestate.
    ///
    /// Additionally, this function also protects the receiver from accidentally subtracting fees
    /// from their own outputs: when a sender is sending a proposal,
    /// they can select an output which they want the receiver to subtract fees from to account for
    /// the increased transaction size. If a sender specifies a receiver output for this purpose, this
    /// function sets that parameter to None so that it is ignored in subsequent steps of the
    /// receiver flow. This protects the receiver from accidentally subtracting fees from their own
    /// outputs.
    #[cfg_attr(not(feature = "v1"), allow(dead_code))]
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<WantsOutputs, ReplyableError> {
        let owned_vouts = self.original.identify_receiver_outputs(is_receiver_output)?;
        // In case of there being multiple outputs paying to the receiver, we select the first one
        // as the `change_vout`, which we will default to when making single output changes in
        // future mutating typestates.
        Ok(WantsOutputs::new(self.original, owned_vouts))
    }
}

/// Validate the request headers for a Payjoin request
///
/// [`RequestError`] should only be produced here.
fn validate_body(headers: impl Headers, body: &[u8]) -> Result<&[u8], RequestError> {
    let content_type = headers
        .get_header("content-type")
        .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
    if !content_type.starts_with("text/plain") {
        return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
    }

    let content_length = headers
        .get_header("content-length")
        .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
        .parse::<usize>()
        .map_err(InternalRequestError::InvalidContentLength)?;
    if body.len() != content_length {
        return Err(InternalRequestError::ContentLengthMismatch {
            expected: content_length,
            actual: body.len(),
        }
        .into());
    }

    Ok(body)
}

impl crate::receive::common::WantsFeeRange {
    /// Applies additional fee contribution now that the receiver has contributed inputs
    /// and may have added new outputs.
    ///
    /// How much the receiver ends up paying for fees depends on how much the sender stated they
    /// were willing to pay in the parameters of the original proposal. For additional
    /// inputs, fees will be subtracted from the sender's outputs as much as possible until we hit
    /// the limit the sender specified in the Payjoin parameters. Any remaining fees for the new inputs
    /// will be then subtracted from the change output of the receiver.
    /// Fees for additional outputs are always subtracted from the receiver's outputs.
    ///
    /// `max_effective_fee_rate` is the maximum effective fee rate that the receiver is
    /// willing to pay for their own input/output contributions. A `max_effective_fee_rate`
    /// of zero indicates that the receiver is not willing to pay any additional
    /// fees. Errors if the final effective fee rate exceeds `max_effective_fee_rate`.
    ///
    /// If not provided, `min_fee_rate` and `max_effective_fee_rate` default to the
    /// minimum possible relay fee.
    ///
    /// The minimum effective fee limit is the highest of the minimum limit set by the sender in
    /// the original proposal parameters and the limit passed in the `min_fee_rate` parameter.
    pub fn apply_fee_range(
        self,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<ProvisionalProposal, ReplyableError> {
        let psbt_context = self._apply_fee_range(min_fee_rate, max_effective_fee_rate)?;
        Ok(ProvisionalProposal { psbt_context })
    }
}

/// Typestate for a checked proposal which had both the outputs and the inputs modified
/// by the receiver. The receiver may sign and finalize the Payjoin proposal which will be sent to
/// the sender for their signature.
///
/// Call [`Self::finalize_proposal`] to return a finalized [`PayjoinProposal`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionalProposal {
    psbt_context: PsbtContext,
}

impl ProvisionalProposal {
    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of two steps:
    ///   1. Remove all sender signatures which were received with the original PSBT as these signatures are now invalid.
    ///   2. Sign and finalize the resulting PSBT using the passed `wallet_process_psbt` signing function.
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> Result<PayjoinProposal, ReplyableError> {
        let finalized_psbt = self
            .psbt_context
            .finalize_proposal(wallet_process_psbt)
            .map_err(|e| ReplyableError::Implementation(ImplementationError::new(e)))?;
        Ok(PayjoinProposal { payjoin_psbt: finalized_psbt })
    }
}

/// A finalized Payjoin proposal, complete with fees and receiver signatures, that the sender
/// should find acceptable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayjoinProposal {
    payjoin_psbt: Psbt,
}

impl PayjoinProposal {
    /// The UTXOs that would be spent by this Payjoin transaction.
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.payjoin_psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    /// The Payjoin Proposal PSBT.
    pub fn psbt(&self) -> &Psbt { &self.payjoin_psbt }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::absolute::{LockTime, Time};
    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Input;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::{
        Address, Amount, Network, OutPoint, PubkeyHash, ScriptBuf, Sequence, TapLeafHash,
        Transaction,
    };
    use payjoin_test_utils::{
        DUMMY20, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, QUERY_PARAMS, RECEIVER_INPUT_CONTRIBUTION,
    };

    use super::*;
    use crate::receive::error::{InternalOutputSubstitutionError, InternalSelectionError};
    use crate::receive::PayloadError;
    use crate::Version;

    #[derive(Debug, Clone)]
    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    #[test]
    fn test_parse_body() {
        let body = ORIGINAL_PSBT.as_bytes().to_vec();
        let headers = MockHeaders::new((body.len() + 1) as u64);

        let validated_request = validate_body(headers.clone(), body.as_slice());
        assert!(validated_request.is_err());

        match validated_request {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(
                    error.to_string(),
                    RequestError::from(InternalRequestError::ContentLengthMismatch {
                        expected: body.len() + 1,
                        actual: body.len(),
                    })
                    .to_string()
                );
            }
        }
    }

    #[test]
    fn test_from_request() -> Result<(), Box<dyn std::error::Error>> {
        let body = ORIGINAL_PSBT.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        let validated_request = validate_body(headers.clone(), body);
        assert!(validated_request.is_ok());

        let proposal = UncheckedProposal::from_request(body, QUERY_PARAMS, headers)?;

        let witness_utxo = proposal.original.psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("witness_utxo should be present");
        let address =
            Address::from_script(&witness_utxo.script_pubkey, bitcoin::params::Params::MAINNET)?;
        assert_eq!(address.address_type(), Some(AddressType::P2sh));

        assert_eq!(proposal.original.params.v, Version::One);
        assert_eq!(
            proposal.original.params.additional_fee_contribution,
            Some((Amount::from_sat(182), 0))
        );
        Ok(())
    }

    fn unchecked_proposal_from_test_vector() -> UncheckedProposal {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::One])
            .expect("Could not parse params from query pairs");
        UncheckedProposal { original: Original { psbt: PARSED_ORIGINAL_PSBT.clone(), params } }
    }

    fn maybe_inputs_owned_from_test_vector() -> MaybeInputsOwned {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::One])
            .expect("Could not parse params from query pairs");
        MaybeInputsOwned { original: Original { psbt: PARSED_ORIGINAL_PSBT.clone(), params } }
    }

    fn wants_outputs_from_test_vector(proposal: UncheckedProposal) -> WantsOutputs {
        proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .expect("No inputs should be owned")
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(&mut |script| {
                let network = Network::Bitcoin;
                Ok(Address::from_script(script, network).unwrap()
                    == Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
                        .unwrap()
                        .require_network(network)
                        .unwrap())
            })
            .expect("Receiver output should be identified")
    }

    fn provisional_proposal_from_test_vector(proposal: UncheckedProposal) -> ProvisionalProposal {
        wants_outputs_from_test_vector(proposal)
            .commit_outputs()
            .commit_inputs()
            .apply_fee_range(None, None)
            .expect("Contributed inputs should allow for valid fee contributions")
    }

    #[test]
    fn test_mutable_receiver_state_closures() {
        let mut call_count = 0;
        let maybe_inputs_owned = maybe_inputs_owned_from_test_vector();

        fn mock_callback(call_count: &mut usize, ret: bool) -> Result<bool, ImplementationError> {
            *call_count += 1;
            Ok(ret)
        }

        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| mock_callback(&mut call_count, false));
        assert_eq!(call_count, 1);

        let outputs_unknown = maybe_inputs_seen
            .map_err(|_| "Check inputs owned closure failed".to_string())
            .expect("Next receiver state should be accessible")
            .check_no_inputs_seen_before(&mut |_| mock_callback(&mut call_count, false));
        assert_eq!(call_count, 2);

        let _wants_outputs = outputs_unknown
            .map_err(|_| "Check no inputs seen closure failed".to_string())
            .expect("Next receiver state should be accessible")
            .identify_receiver_outputs(&mut |_| mock_callback(&mut call_count, true));
        // there are 2 receiver outputs so we should expect this callback to run twice incrementing
        // call count twice
        assert_eq!(call_count, 4);
    }

    #[test]
    fn is_output_substitution_disabled() {
        let mut proposal = unchecked_proposal_from_test_vector();
        let payjoin = wants_outputs_from_test_vector(proposal.clone());
        assert_eq!(payjoin.output_substitution(), OutputSubstitution::Enabled);

        proposal.original.params.output_substitution = OutputSubstitution::Disabled;
        let payjoin = wants_outputs_from_test_vector(proposal);
        assert_eq!(payjoin.output_substitution(), OutputSubstitution::Disabled);
    }

    #[test]
    fn unchecked_proposal_min_fee() {
        let proposal = unchecked_proposal_from_test_vector();

        let min_fee_rate =
            proposal.original.psbt_fee_rate().expect("Feerate calculation should not fail");
        let _ = proposal
            .clone()
            .check_broadcast_suitability(Some(min_fee_rate), |_| Ok(true))
            .expect("Broadcast suitability check with appropriate min_fee_rate should succeed");
        assert_eq!(proposal.original.psbt_fee_rate().unwrap(), min_fee_rate);

        let min_fee_rate = FeeRate::MAX;
        let expected_err =
            ReplyableError::Payload(PayloadError(InternalPayloadError::PsbtBelowFeeRate(
                proposal.original.psbt_fee_rate().unwrap(),
                min_fee_rate,
            )));
        let proposal_below_min_fee = proposal
            .check_broadcast_suitability(Some(min_fee_rate), |_| Ok(true))
            .expect_err("Broadcast suitability with min_fee_rate below minimum should fail");
        assert_eq!(proposal_below_min_fee.to_string(), expected_err.to_string());
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        let proposal = unchecked_proposal_from_test_vector();
        assert_eq!(proposal.original.psbt_fee_rate().unwrap().to_sat_per_vb_floor(), 2);
        let payjoin = wants_outputs_from_test_vector(proposal).commit_outputs().commit_inputs();

        {
            let mut payjoin = payjoin.clone();
            let psbt = payjoin.apply_fee(None, None);
            assert!(psbt.is_ok(), "Payjoin should be a valid PSBT");
        }
        {
            let mut payjoin = payjoin.clone();
            let psbt = payjoin.apply_fee(None, Some(FeeRate::ZERO));
            assert!(psbt.is_ok(), "Payjoin should be a valid PSBT");
        }
    }

    #[test]
    fn empty_candidates_inputs() {
        let proposal = unchecked_proposal_from_test_vector();
        let wants_inputs = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .expect("No inputs should be owned")
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(&mut |script| {
                let network = Network::Bitcoin;
                let target_address = Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
                    .map_err(ImplementationError::new)?
                    .require_network(network)
                    .map_err(ImplementationError::new)?;

                let script_address =
                    Address::from_script(script, network).map_err(ImplementationError::new)?;
                Ok(script_address == target_address)
            })
            .expect("Receiver output should be identified")
            .commit_outputs();
        let empty_candidate_inputs: Vec<InputPair> = vec![];
        let result = wants_inputs.try_preserving_privacy(empty_candidate_inputs);
        assert_eq!(
            result.unwrap_err(),
            SelectionError::from(InternalSelectionError::Empty),
            "try_preserving_privacy should fail with empty candidate inputs"
        );
    }

    #[test]
    fn sender_specifies_excessive_fee_rate() {
        let mut proposal = unchecked_proposal_from_test_vector();
        assert_eq!(proposal.original.psbt_fee_rate().unwrap().to_sat_per_vb_floor(), 2);
        // Specify excessive fee rate in sender params
        proposal.original.params.min_fee_rate = FeeRate::from_sat_per_vb_unchecked(1000);
        let proposal_psbt = Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).unwrap();
        let input = InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            proposal_psbt.inputs[1].clone(),
            None,
        )
        .unwrap();
        let mut payjoin = wants_outputs_from_test_vector(proposal)
            .commit_outputs()
            .contribute_inputs(vec![input])
            .expect("Failed to contribute inputs")
            .commit_inputs();
        let additional_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: payjoin.original_psbt.unsigned_tx.output[0].script_pubkey.clone(),
        };
        payjoin.payjoin_psbt.unsigned_tx.output.push(additional_output);
        let mut payjoin_clone = payjoin.clone();
        let psbt = payjoin.apply_fee(None, Some(FeeRate::from_sat_per_vb_unchecked(1000)));
        assert!(psbt.is_ok(), "Payjoin should be a valid PSBT");
        let psbt = payjoin_clone.apply_fee(None, Some(FeeRate::from_sat_per_vb_unchecked(995)));
        match psbt {
            Err(InternalPayloadError::FeeTooHigh(proposed, max)) => {
                assert_eq!(FeeRate::from_str("249630").unwrap(), proposed);
                assert_eq!(FeeRate::from_sat_per_vb_unchecked(995), max);
            }
            _ => panic!(
                "Payjoin exceeds receiver fee preference and should error or unexpected error type"
            ),
        }
    }

    #[test]
    fn additional_input_weight_matches_known_weight() {
        // All expected input weights pulled from:
        // https://bitcoin.stackexchange.com/questions/84004/how-do-virtual-size-stripped-size-and-raw-size-compare-between-legacy-address-f#84006
        // Input weight for a single P2PKH (legacy) receiver input
        let p2pkh_proposal = WantsFeeRange {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAb2qhegy47hqffxh/UH5Qjd/G3sBH6cW2QSXZ86nbY3nAAAAAAD9////AhXKBSoBAAAAFgAU4TiLFD14YbpddFVrZa3+Zmz96yQQJwAAAAAAABYAFB4zA2o+5MsNRT/j+0twLi5VbwO9AAAAAAABAIcCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBSgD/////AgDyBSoBAAAAGXapFGUxpU6cGldVpjUm9rV2B+jTlphDiKwAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABB2pHMEQCIGsOxO/bBv20bd68sBnEU3cxHR8OxEcUroL3ENhhjtN3AiB+9yWuBGKXu41hcfO4KP7IyLLEYc6j8hGowmAlCPCMPAEhA6WNSN4CqJ9F+42YKPlIFN0wJw7qawWbdelGRMkAbBRnACICAsdIAjsfMLKgfL2J9rfIa8yKdO1BOpSGRIFbFMBdTsc9GE4roNNUAACAAQAAgAAAAIABAAAAAAAAAAAA").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAtTRxwAtk38fRMP3ffdKkIi5r+Ss9AjaO8qEv+eQ/ho3AAAAAAD9////vaqF6DLjuGp9/GH9QflCN38bewEfpxbZBJdnzqdtjecAAAAAAP3///8CgckFKgEAAAAWABThOIsUPXhhul10VWtlrf5mbP3rJBAZBioBAAAAFgAUiDIby0wSbj1kv3MlvwoEKw3vNZUAAAAAAAEAhwIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFoAP////8CAPIFKgEAAAAZdqkUPXhu3I6D9R0wUpvTvvUm+VGNcNuIrAAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBIgDyBSoBAAAAGXapFD14btyOg/UdMFKb0771JvlRjXDbiKwBB2pHMEQCIGzKy8QfhHoAY0+LZCpQ7ZOjyyXqaSBnr89hH3Eg/xsGAiB3n8hPRuXCX/iWtURfXoJNUFu3sLeQVFf1dDFCZPN0dAEhA8rTfrwcq6dEBSNOrUfNb8+dm7q77vCtfdOmWx0HfajRAAEAhwIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFKAP////8CAPIFKgEAAAAZdqkUZTGlTpwaV1WmNSb2tXYH6NOWmEOIrAAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAAAAA==").unwrap(),
            params: Params::default(),
            change_vout: 0,
            receiver_inputs: vec![
                InputPair::new(
                    TxIn{
                        previous_output: OutPoint::from_str("371afe90e7bf84ca3bda08f4ace4afb988904af77df7c3441f7f932d00c7d1d4:0").unwrap(),
                        ..Default::default()
                    }, Input {
                        witness_utxo: Some(TxOut {
                            value: Amount::from_sat(5_000_000_000),
                            script_pubkey: ScriptBuf::from_hex("76a9143d786edc8e83f51d30529bd3bef526f9518d70db88ac").unwrap(),
                        }),
                        ..Default::default()
                    }, None)
                .unwrap()],
        };
        assert_eq!(
            p2pkh_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(592)
        );

        // Input weight for a single nested P2WPKH (nested segwit) receiver input
        let nested_p2wpkh_proposal = WantsFeeRange {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAeOsT9cRWRz3te+bgmtweG1vDLkdSH4057NuoodDNPFWAAAAAAD9////AhAnAAAAAAAAFgAUtp3bPFM/YWThyxD5Cc9OR4mb8tdMygUqAQAAABYAFODlplDoE6EGlZvmqoUngBgsu8qCAAAAAAABAIUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBZwD/////AgDyBSoBAAAAF6kU2JnIn4Mmcb5kuF3EYeFei8IB43qHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPIFKgEAAAAXqRTYmcifgyZxvmS4XcRh4V6LwgHjeocBBxcWABSPGoPK1yl60X4Z9OfA7IQPUWCgVwEIawJHMEQCICZG3s2cbulPnLTvK4TwlKhsC+cem8tD2GjZZ3eMJD7FAiADh/xwv0ib8ksOrj1M27DYLiw7WFptxkMkE2YgiNMRVgEhAlDMm5DA8kU+QGiPxEWUyV1S8+XGzUOepUOck257ZOhkAAAiAgP+oMbeca66mt+UtXgHm6v/RIFEpxrwG7IvPDim5KWHpBgfVHrXVAAAgAEAAIAAAACAAQAAAAAAAAAA").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAuXYOTUaVRiB8cPPhEXzcJ72/SgZOPEpPx5pkG0fNeGCAAAAAAD9////46xP1xFZHPe175uCa3B4bW8MuR1IfjTns26ih0M08VYAAAAAAP3///8CEBkGKgEAAAAWABQHuuu4H4fbQWV51IunoJLUtmMTfEzKBSoBAAAAFgAU4OWmUOgToQaVm+aqhSeAGCy7yoIAAAAAAAEBIADyBSoBAAAAF6kUQ4BssmVBS3r0s95c6dl1DQCHCR+HAQQWABQbDc333XiiOeEXroP523OoYNb1aAABAIUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBZwD/////AgDyBSoBAAAAF6kU2JnIn4Mmcb5kuF3EYeFei8IB43qHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPIFKgEAAAAXqRTYmcifgyZxvmS4XcRh4V6LwgHjeocBBxcWABSPGoPK1yl60X4Z9OfA7IQPUWCgVwEIawJHMEQCICZG3s2cbulPnLTvK4TwlKhsC+cem8tD2GjZZ3eMJD7FAiADh/xwv0ib8ksOrj1M27DYLiw7WFptxkMkE2YgiNMRVgEhAlDMm5DA8kU+QGiPxEWUyV1S8+XGzUOepUOck257ZOhkAAAA").unwrap(),
            params: Params::default(),
            change_vout: 0,
            receiver_inputs: vec![
                InputPair::new(
                    TxIn {
                        previous_output: OutPoint::from_str("82e1351f6d90691e3f29f1381928fdf69e70f34584cfc3f18118551a3539d8e5:0").unwrap(),
                        ..Default::default()
                    },
                    Input {
                        witness_utxo: Some(TxOut {
                            value: Amount::from_sat(5_000_000_000),
                            script_pubkey: ScriptBuf::from_hex("a91443806cb265414b7af4b3de5ce9d9750d0087091f87").unwrap(),
                        }),
                        redeem_script: Some(ScriptBuf::from_hex("00141b0dcdf7dd78a239e117ae83f9db73a860d6f568").unwrap()),
                        ..Default::default()
                    }, None)
                .unwrap()],
        };
        assert_eq!(
            nested_p2wpkh_proposal
                .additional_input_weight()
                .expect("should calculate input weight"),
            Weight::from_wu(364)
        );

        // Input weight for a single P2WPKH (native segwit) receiver input
        let p2wpkh_proposal = WantsFeeRange {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAASom13OiXZIr3bKk+LtUndZJYqdHQQU8dMs1FZ93IctIAAAAAAD9////AmPKBSoBAAAAFgAU6H98YM9NE1laARQ/t9/90nFraf4QJwAAAAAAABYAFBPJFmYuJBsrIaBBp9ur98pMSKxhAAAAAAABAIQCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBWwD/////AgDyBSoBAAAAFgAUjTJXmC73n+URSNdfgbS6Oa6JyQYAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABAR8A8gUqAQAAABYAFI0yV5gu95/lEUjXX4G0ujmuickGAQhrAkcwRAIgUqbHS0difIGTRwN56z2/EiqLQFWerfJspyjuwsGSCXcCIA3IRTu8FVgniU5E4gecAMeegVnlTbTVfFyusWhQ2kVVASEDChVRm26KidHNWLdCLBTq5jspGJr+AJyyMqmUkvPkwFsAIgIDeBqmRB3ESjFWIp+wUXn/adGZU3kqWGjdkcnKpk8bAyUY94v8N1QAAIABAACAAAAAgAEAAAAAAAAAAAA=").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAiom13OiXZIr3bKk+LtUndZJYqdHQQU8dMs1FZ93IctIAAAAAAD9////NG21aH8Vat3thaVmPvWDV/lvRmymFHeePcfUjlyngHIAAAAAAP3///8CH8oFKgEAAAAWABTof3xgz00TWVoBFD+33/3ScWtp/hAZBioBAAAAFgAU1mbnqky3bMxfmm0OgFaQCAs5fsoAAAAAAAEAhAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFbAP////8CAPIFKgEAAAAWABSNMleYLvef5RFI11+BtLo5ronJBgAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBHwDyBSoBAAAAFgAUjTJXmC73n+URSNdfgbS6Oa6JyQYAAQCEAgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8DAWcA/////wIA8gUqAQAAABYAFJFtkfHTt3y1EDMaN6CFjjNWtpCRAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEfAPIFKgEAAAAWABSRbZHx07d8tRAzGjeghY4zVraQkQEIawJHMEQCIDTC49IB9AnItqd8zy5RDc05f2ApBAfJ5x4zYfj3bsD2AiAQvvSt5ipScHcUwdlYB9vFnEi68hmh55M5a5e+oWvxMAEhAqErVSVulFb97/r5KQryOS1Xgghff8R7AOuEnvnmslQ5AAAA").unwrap(),
            params: Params::default(),
            change_vout: 0,
            receiver_inputs: vec![
                InputPair::new(
                    TxIn {
                        previous_output: OutPoint::from_str("7280a75c8ed4c73d9e7714a66c466ff95783f53e66a585eddd6a157f68b56d34:0").unwrap(),
                        ..Default::default()
                    }, Input {
                        witness_utxo: Some(TxOut {
                            value: Amount::from_sat(5_000_000_000),
                            script_pubkey: ScriptBuf::from_hex("0014916d91f1d3b77cb510331a37a0858e3356b69091").unwrap(),
                        }),
                        ..Default::default()
                    }, None)
                .unwrap()],
        };
        assert_eq!(
            p2wpkh_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(272)
        );

        // Input weight for a single P2TR (taproot) receiver input
        let p2tr_proposal = WantsFeeRange {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAU/CHxd1oi9Lq1xOD2GnHe0hsQdGJ2mkpYkmeasTj+w1AAAAAAD9////Am3KBSoBAAAAFgAUqJL/PDPnHeihhNhukTz8QEdZbZAQJwAAAAAAABYAFInyO0NQF7YR22Sm0YTPGm6yf19YAAAAAAABASsA8gUqAQAAACJRIGOPekNKFs9ASLj3FdlCLiou/jdPUegJGzlA111A80MAAQhCAUC3zX8eSeL8+bAo6xO0cpon83UsJdttiuwfMn/pBwub82rzMsoS6HZNXzg7hfcB3p1uj8JmqsBkZwm8k6fnU2peACICA+u+FjwmhEgWdjhEQbO49D0NG8iCYUoqhlfsj0LN7hiRGOcVI65UAACAAQAAgAAAAIABAAAAAAAAAAAA").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAk/CHxd1oi9Lq1xOD2GnHe0hsQdGJ2mkpYkmeasTj+w1AAAAAAD9////Fz+ELsYp/55j6+Jl2unG9sGvpHTiSyzSORBvtu1GEB4AAAAAAP3///8CM8oFKgEAAAAWABSokv88M+cd6KGE2G6RPPxAR1ltkBAZBioBAAAAFgAU68J5imRcKy3g5JCT3bEoP9IXEn0AAAAAAAEBKwDyBSoBAAAAIlEgY496Q0oWz0BIuPcV2UIuKi7+N09R6AkbOUDXXUDzQwAAAQErAPIFKgEAAAAiUSCfbbX+FHJbzC71eEFLsMjDouMJbu8ogeR0eNoNxMM9CwEIQwFBeyOLUebV/YwpaLTpLIaTXaSiPS7Dn6o39X4nlUzQLfb6YyvCAsLA5GTxo+Zb0NUINZ8DaRyUWknOpU/Jzuwn2gEAAAA=").unwrap(),
            params: Params::default(),
            change_vout: 0,
            receiver_inputs: vec![
                InputPair::new(
                    TxIn {
                        previous_output: OutPoint::from_str("1e1046edb66f1039d22c4be274a4afc1f6c6e9da65e2eb639eff29c62e843f17:0").unwrap(),
                        ..Default::default()
                    }, Input {
                        witness_utxo: Some(TxOut {
                            value: Amount::from_sat(5_000_000_000),
                            script_pubkey: ScriptBuf::from_hex("51209f6db5fe14725bcc2ef578414bb0c8c3a2e3096eef2881e47478da0dc4c33d0b").unwrap(),
                        }),
                        ..Default::default()
                    }, None)
                .unwrap()],
        };
        assert_eq!(
            p2tr_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(230)
        );
    }

    #[test]
    fn test_pjos_disabled() {
        let mut proposal = unchecked_proposal_from_test_vector();
        proposal.original.params.output_substitution = OutputSubstitution::Disabled;
        let wants_outputs = wants_outputs_from_test_vector(proposal);
        let script_pubkey = &wants_outputs.original_psbt.unsigned_tx.output
            [wants_outputs.change_vout]
            .script_pubkey;

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let unchanged_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert!(
            unchanged_amount.is_ok(),
            "Not touching the receiver output amount is always allowed"
        );
        assert_ne!(wants_outputs.payjoin_psbt, unchanged_amount.unwrap().payjoin_psbt);

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value
                + Amount::ONE_SAT;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let increased_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert!(
            increased_amount.is_ok(),
            "Increasing the receiver output amount is always allowed"
        );
        assert_ne!(wants_outputs.payjoin_psbt, increased_amount.unwrap().payjoin_psbt);

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value
                - Amount::ONE_SAT;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let decreased_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert_eq!(
            decreased_amount.unwrap_err(),
            OutputSubstitutionError::from(
                InternalOutputSubstitutionError::DecreasedValueWhenDisabled
            ),
            "Payjoin receiver amount has been decreased and should error"
        );

        let script = Script::new();
        let replace_receiver_script_pubkey = wants_outputs.substitute_receiver_script(script);
        assert_eq!(
            replace_receiver_script_pubkey.unwrap_err(),
            OutputSubstitutionError::from(
                InternalOutputSubstitutionError::ScriptPubKeyChangedWhenDisabled
            ),
            "Payjoin receiver script pubkey has been modified and should error"
        );
    }

    #[test]
    fn test_avoid_uih_one_output() {
        let proposal = unchecked_proposal_from_test_vector();
        let proposal_psbt = Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).unwrap();
        let input = InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            proposal_psbt.inputs[1].clone(),
            None,
        )
        .unwrap();
        let input_iter = [input].into_iter();
        let mut payjoin = wants_outputs_from_test_vector(proposal)
            .commit_outputs()
            .contribute_inputs(input_iter.clone())
            .expect("Failed to contribute inputs");

        payjoin.payjoin_psbt.outputs.pop();
        let avoid_uih = payjoin.avoid_uih(input_iter);
        assert_eq!(
            avoid_uih.unwrap_err(),
            SelectionError::from(InternalSelectionError::UnsupportedOutputLength),
            "Payjoin below minimum allowed outputs for avoid uih and should error"
        );
    }

    /// Add keypath data to psbt to be prepared and verify it is excluded from the final PSBT
    /// See: <https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#senders-payjoin-proposal-checklist>
    #[test]
    fn test_prepare_psbt_excludes_keypaths() {
        let proposal = unchecked_proposal_from_test_vector();
        let mut processed_psbt = proposal.original.psbt.clone();

        let secp = Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut bitcoin::key::rand::thread_rng());
        let xpriv = Xpriv::new_master(Network::Bitcoin, &[]).expect("Could not generate new xpriv");
        let (x_only, _) = pk.x_only_public_key();

        processed_psbt.xpub.insert(
            Xpub::from_priv(&secp, &xpriv),
            (Fingerprint::default(), DerivationPath::default()),
        );

        for input in &mut processed_psbt.inputs {
            input.bip32_derivation.insert(pk, (Fingerprint::default(), DerivationPath::default()));
            input.tap_key_origins.insert(
                x_only,
                (
                    vec![TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript)],
                    (Fingerprint::default(), DerivationPath::default()),
                ),
            );
            input.tap_internal_key = Some(x_only);
        }

        for output in &mut processed_psbt.outputs {
            output.bip32_derivation.insert(pk, (Fingerprint::default(), DerivationPath::default()));
            output.tap_key_origins.insert(
                x_only,
                (
                    vec![TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript)],
                    (Fingerprint::default(), DerivationPath::default()),
                ),
            );
            output.tap_internal_key = Some(x_only);
        }

        let provisional = provisional_proposal_from_test_vector(proposal);
        let payjoin_proposal =
            provisional.finalize_proposal(|_| Ok(processed_psbt.clone())).expect("Valid psbt");

        assert!(payjoin_proposal.payjoin_psbt.xpub.is_empty());

        for input in &payjoin_proposal.payjoin_psbt.inputs {
            assert!(input.bip32_derivation.is_empty());
            assert!(input.tap_key_origins.is_empty());
            assert!(input.tap_internal_key.is_none());
        }

        for output in &payjoin_proposal.payjoin_psbt.outputs {
            assert!(output.bip32_derivation.is_empty());
            assert!(output.tap_key_origins.is_empty());
            assert!(output.tap_internal_key.is_none());
        }
    }

    #[test]
    fn test_multiple_contribute_inputs() {
        let proposal = unchecked_proposal_from_test_vector();
        let wants_inputs = wants_outputs_from_test_vector(proposal).commit_outputs();
        let txout = TxOut {
            value: Amount::from_sat(123),
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(DUMMY20)),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![txout.clone()],
        };
        let ot1 = OutPoint { txid: tx.compute_txid(), vout: 0 };
        let ot2 = OutPoint { txid: tx.compute_txid(), vout: 1 };

        let input_pair_1 = InputPair::new(
            TxIn { previous_output: ot1, sequence: Sequence::MAX, ..Default::default() },
            Input { witness_utxo: Some(txout.clone()), ..Default::default() },
            None,
        )
        .unwrap();
        let input_pair_2 = InputPair::new(
            TxIn { previous_output: ot2, sequence: Sequence::MAX, ..Default::default() },
            Input { witness_utxo: Some(txout), ..Default::default() },
            None,
        )
        .unwrap();

        let wants_inputs = wants_inputs.contribute_inputs(vec![input_pair_1.clone()]).unwrap();
        assert_eq!(wants_inputs.receiver_inputs.len(), 1);
        assert_eq!(wants_inputs.receiver_inputs[0], input_pair_1);
        // Contribute the same input again, and a new input.
        // TODO: if we ever decide to fix contribute duplicate inputs, we need to update this test.
        let wants_inputs = wants_inputs
            .contribute_inputs(vec![input_pair_2.clone(), input_pair_1.clone()])
            .unwrap();
        assert_eq!(wants_inputs.receiver_inputs.len(), 3);
        assert_eq!(wants_inputs.receiver_inputs[0], input_pair_1);
        assert_eq!(wants_inputs.receiver_inputs[1], input_pair_2);
        assert_eq!(wants_inputs.receiver_inputs[2], input_pair_1);
    }

    #[test]
    fn test_finalize_proposal_invalid_payjoin_proposal() {
        let proposal = unchecked_proposal_from_test_vector();
        let provisional = provisional_proposal_from_test_vector(proposal);
        let empty_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        };
        let other_psbt = Psbt::from_unsigned_tx(empty_tx).expect("Valid unsigned tx");
        let err = provisional.clone().finalize_proposal(|_| Ok(other_psbt.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Internal Server Error: Ntxid mismatch: expected {}, got {}",
                provisional.psbt_context.payjoin_psbt.unsigned_tx.compute_txid(),
                other_psbt.unsigned_tx.compute_txid()
            )
        );
    }
}
