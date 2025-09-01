//! Receive BIP 78 Payjoin v1
//!
//! This module contains types and methods used to receive payjoin via BIP78.
//! Usage is pretty simple:
//!
//! 1. Generate a pj_uri [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
//!    using [`build_v1_pj_uri`]
//! 2. Listen for a sender's request on the `pj` endpoint
//! 3. Parse the request using
//!    [`UncheckedOriginalPayload::from_request()`]
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

impl UncheckedOriginalPayload {
    pub fn from_request(body: &[u8], query: &str, headers: impl Headers) -> Result<Self, Error> {
        let validated_body = validate_body(headers, body).map_err(ProtocolError::V1)?;

        let base64 = std::str::from_utf8(validated_body).map_err(InternalPayloadError::Utf8)?;

        let (psbt, params) = crate::receive::parse_payload(base64, query, SUPPORTED_VERSIONS)
            .map_err(ProtocolError::OriginalPayload)?;

        Ok(Self { original: OriginalPayload { psbt, params } })
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
pub struct UncheckedOriginalPayload {
    original: OriginalPayload,
}

impl UncheckedOriginalPayload {
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
    ) -> Result<MaybeInputsOwned, Error> {
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
    pub(crate) original: OriginalPayload,
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
    ) -> Result<MaybeInputsSeen, Error> {
        self.original.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { original: self.original })
    }
}

/// Typestate to check that the original PSBT has no inputs that the receiver has seen before.
///
/// Call [`Self::check_no_inputs_seen_before`] to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    original: OriginalPayload,
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
    ) -> Result<OutputsUnknown, Error> {
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
    original: OriginalPayload,
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
    ) -> Result<WantsOutputs, Error> {
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
    ) -> Result<ProvisionalProposal, Error> {
        let psbt_context =
            self.calculate_psbt_context_with_fee_range(min_fee_rate, max_effective_fee_rate)?;
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
    ) -> Result<PayjoinProposal, Error> {
        let finalized_psbt = self
            .psbt_context
            .finalize_proposal(wallet_process_psbt)
            .map_err(|e| Error::Implementation(ImplementationError::new(e)))?;
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
    use bitcoin::{Address, Amount, Network, Transaction};
    use payjoin_test_utils::{ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, QUERY_PARAMS};

    use super::*;
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

        let proposal = UncheckedOriginalPayload::from_request(body, QUERY_PARAMS, headers)?;

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

    fn unchecked_proposal_from_test_vector() -> UncheckedOriginalPayload {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::One])
            .expect("Could not parse params from query pairs");
        UncheckedOriginalPayload {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
        }
    }

    fn maybe_inputs_owned_from_test_vector() -> MaybeInputsOwned {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::One])
            .expect("Could not parse params from query pairs");
        MaybeInputsOwned {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
        }
    }

    fn wants_outputs_from_test_vector(proposal: UncheckedOriginalPayload) -> WantsOutputs {
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

    fn provisional_proposal_from_test_vector(
        proposal: UncheckedOriginalPayload,
    ) -> ProvisionalProposal {
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
        let proposal_below_min_fee = proposal
            .clone()
            .check_broadcast_suitability(Some(min_fee_rate), |_| Ok(true))
            .expect_err("Broadcast suitability with min_fee_rate below minimum should fail");
        match proposal_below_min_fee {
            Error::Protocol(ProtocolError::OriginalPayload(PayloadError(
                InternalPayloadError::PsbtBelowFeeRate(original_fee_rate, min_fee_rate_param),
            ))) => {
                assert_eq!(original_fee_rate, proposal.original.psbt_fee_rate().unwrap());
                assert_eq!(min_fee_rate_param, min_fee_rate);
            }
            _ => panic!("Expected PsbtBelowFeeRate error, got: {proposal_below_min_fee:?}"),
        }
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
                "Implementation error: Ntxid mismatch: expected {}, got {}",
                provisional.psbt_context.payjoin_psbt.unsigned_tx.compute_txid(),
                other_psbt.unsigned_tx.compute_txid()
            )
        );
    }
}
