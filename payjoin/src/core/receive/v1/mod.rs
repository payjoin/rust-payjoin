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
    let pj_param = PjParam::parse(endpoint)?;
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

/// This is the first typestate after retrieving the sender's proposal. Here the
/// receiver verifies the Original PSBT is broadcastable so it can serve as a
/// fallback if the payjoin fails.
///
/// Non-interactive receivers (e.g. a donation page that generates a fresh QR code
/// per visit) should call [`Self::check_broadcast_suitability`] to confirm the
/// proposal is broadcastable (and optionally above a minimum fee rate), guarding
/// against probing attacks that trick the receiver into revealing its UTXOs.
/// Interactive receivers can skip that check and call
/// [`Self::assume_interactive_receiver`] instead. Either path advances to
/// [`MaybeInputsOwned`].
#[derive(Debug, Clone)]
pub struct UncheckedOriginalPayload {
    original: OriginalPayload,
}

impl UncheckedOriginalPayload {
    /// Check that the sender's Original PSBT is suitable for broadcast, ensuring
    /// it can be used as a fallback if the payjoin does not complete.
    ///
    /// Returns a [`MaybeInputsOwned`] to continue validation.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsOwned, Error> {
        self.original.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(MaybeInputsOwned { original: self.original })
    }

    /// Skip the current typestate's validations.
    ///
    /// Use this for interactive receivers, which manually create Payjoin URIs and so
    /// are not exposed to the probing attacks the checks guard against.
    ///
    /// Returns a [`MaybeInputsOwned`].
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        MaybeInputsOwned { original: self.original }
    }
}

/// Typestate to check that the Original PSBT has no inputs owned by the receiver.
///
/// At this point, the Original PSBT has been verified as broadcastable; the receiver
/// can call [`Self::extract_tx_to_schedule_broadcast`] to schedule a fallback broadcast
/// in case the payjoin fails.
///
/// Call [`Self::check_inputs_not_owned`] to advance to [`MaybeInputsSeen`] to continue
/// validation.
#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    pub(crate) original: OriginalPayload,
}

impl MaybeInputsOwned {
    /// Extract the transaction from the Original PSBT for scheduling broadcast as a
    /// fallback in case the payjoin does not complete.
    ///
    /// Returns the extracted [`bitcoin::Transaction`].
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.original.psbt.clone().extract_tx_unchecked_fee_rate()
    }

    /// Check that none of the Original PSBT's inputs belong to the receiver,
    /// preventing an attacker from spending the receiver's own inputs.
    ///
    /// Returns a [`MaybeInputsSeen`] to continue validation.
    pub fn check_inputs_not_owned(
        self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsSeen, Error> {
        self.original.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { original: self.original })
    }
}

/// Typestate to check that the Original PSBT has no inputs the receiver has seen before.
///
/// This check prevents the following attacks:
/// 1. Probing attacks, where the sender uses the exact same proposal (or with
///    minimal change) to have the receiver reveal their UTXO set by contributing
///    to all proposals with different inputs and sending them back to the receiver.
/// 2. Re-entrant payjoin, where the sender uses the payjoin PSBT of a previous
///    payjoin as the Original PSBT of the current, new payjoin.
///
/// Call [`Self::check_no_inputs_seen_before`] to advance to [`OutputsUnknown`] to
/// continue validation.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    original: OriginalPayload,
}
impl MaybeInputsSeen {
    /// Check that none of the inputs have been seen before, preventing input
    /// probing and replay attacks (where inputs have been used in a previous
    /// payjoin attempt).
    ///
    /// Returns an [`OutputsUnknown`] to continue validation.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<OutputsUnknown, Error> {
        self.original.check_no_inputs_seen_before(is_known)?;
        Ok(OutputsUnknown { original: self.original })
    }
}

/// Typestate to check that the outputs of the Original PSBT actually pay the receiver.
///
/// The receiver should only accept Original PSBTs from the sender that actually send
/// them money. Call [`Self::identify_receiver_outputs`] to advance to [`WantsOutputs`]
/// to continue the proposal.
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    original: OriginalPayload,
}

impl OutputsUnknown {
    /// Identify which outputs in the original transaction belong to the receiver
    /// and ensure at least one output pays the receiver.
    ///
    /// If the sender designated a receiver output for fee subtraction, that designation
    /// is cleared so the receiver does not accidentally subtract fees from their own output.
    ///
    /// Returns a [`WantsOutputs`] to continue the proposal.
    #[cfg_attr(not(feature = "v1"), allow(dead_code))]
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<WantsOutputs, Error> {
        self.original.identify_receiver_outputs(is_receiver_output)
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
    ///
    /// Returns a [`ProvisionalProposal`].
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

/// Typestate for a checked proposal that the receiver has modified the outputs and
/// inputs of, and is ready to be signed and finalized.
///
/// Call [`Self::finalize_proposal`] to advance to [`PayjoinProposal`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionalProposal {
    psbt_context: PsbtContext,
}

impl ProvisionalProposal {
    /// Finalize the proposal by signing the PSBT via the `wallet_process_psbt` callback.
    ///
    /// Returns the final [`PayjoinProposal`].
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

    /// Extract the PSBT that needs to be signed by the receiver's wallet.
    ///
    /// In some applications the entity that progresses the typestate is different from the
    /// entity that has access to the private keys, so the PSBT to sign must be accessible to
    /// such implementers.
    ///
    /// Returns the Payjoin proposal [`Psbt`] to be signed.
    pub fn psbt_to_sign(&self) -> Psbt { self.psbt_context.psbt_to_sign() }
}

/// Typestate for a signed and finalized Payjoin proposal that is to be sent to the
/// sender for them to sign and broadcast.
///
/// Extract the proposal PSBT with [`Self::psbt`] and respond to the sender's original
/// request with it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayjoinProposal {
    payjoin_psbt: Psbt,
}

impl PayjoinProposal {
    /// Returns the finalized payjoin proposal PSBT.
    pub fn psbt(&self) -> &Psbt { &self.payjoin_psbt }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::absolute::{LockTime, Time};
    use bitcoin::{Address, Network, Transaction};
    use payjoin_test_utils::{
        MAX_ADDITIONAL_FEE_CONTRIBUTION, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT,
        PARSED_PAYJOIN_PROPOSAL, QUERY_PARAMS,
    };

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
            Some((MAX_ADDITIONAL_FEE_CONTRIBUTION, 0))
        );
        Ok(())
    }

    fn unchecked_proposal_from_test_vector() -> UncheckedOriginalPayload {
        let params = Params::from_query_str(QUERY_PARAMS, &[Version::One])
            .expect("Could not parse params from query str");
        UncheckedOriginalPayload {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
        }
    }

    fn maybe_inputs_owned_from_test_vector() -> MaybeInputsOwned {
        let params = Params::from_query_str(QUERY_PARAMS, &[Version::One])
            .expect("Could not parse params from query str");
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

    #[test]
    fn test_getting_psbt_to_sign() {
        let provisional_proposal = ProvisionalProposal {
            psbt_context: PsbtContext {
                payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            },
        };
        let psbt = provisional_proposal.psbt_to_sign();
        assert_eq!(psbt, PARSED_PAYJOIN_PROPOSAL.clone());
    }
}
