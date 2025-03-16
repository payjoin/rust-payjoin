//! Send BIP 78 Payjoin v1
//!
//! This module contains types and methods used to implement sending via [BIP78
//! Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki).
//!
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Construct URI request parameters, a finalized “Original PSBT” paying .amount to .address
//! 3. (optional) Spawn a thread or async task that will broadcast the original PSBT fallback after
//!    delay (e.g. 1 minute) unless canceled
//! 4. Construct the [`Sender`] using [`SenderBuilder`] with the PSBT and payjoin uri
//! 5. Send the request and receive a response by following on the extracted V1Context
//! 6. Sign and finalize the Payjoin Proposal PSBT
//! 7. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be
//! provided by custom implementations or copy the reference
//! [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind,
//! [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or
//! [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own
//! wallet and http client.

use std::io::{BufRead, BufReader};

use bitcoin::psbt::Psbt;
use bitcoin::{FeeRate, ScriptBuf, Weight};
use error::{BuildSenderError, InternalBuildSenderError};
use url::Url;

use super::*;
pub use crate::output_substitution::OutputSubstitution;
use crate::psbt::PsbtExt;
use crate::request::Request;
use crate::{PjUri, MAX_CONTENT_LENGTH};

/// A builder to construct the properties of a `Sender`.
#[derive(Clone)]
pub struct SenderBuilder<'a> {
    pub(crate) psbt: Psbt,
    pub(crate) uri: PjUri<'a>,
    pub(crate) output_substitution: OutputSubstitution,
    pub(crate) fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    /// Decreases the fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub(crate) clamp_fee_contribution: bool,
    pub(crate) min_fee_rate: FeeRate,
}

impl<'a> SenderBuilder<'a> {
    /// Prepare the context from which to make Sender requests
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self {
        Self {
            psbt,
            uri,
            // Sender's optional parameters
            output_substitution: OutputSubstitution::Enabled,
            fee_contribution: None,
            clamp_fee_contribution: false,
            min_fee_rate: FeeRate::ZERO,
        }
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(mut self) -> Self {
        self.output_substitution = OutputSubstitution::Disabled;
        self
    }

    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(self, min_fee_rate: FeeRate) -> Result<Sender, BuildSenderError> {
        // TODO support optional batched payout scripts. This would require a change to
        // build() which now checks for a single payee.
        let mut payout_scripts = std::iter::once(self.uri.address.script_pubkey());

        // Check if the PSBT is a sweep transaction with only one output that's a payout script and no change
        if self.psbt.unsigned_tx.output.len() == 1
            && payout_scripts.all(|script| script == self.psbt.unsigned_tx.output[0].script_pubkey)
        {
            return self.build_non_incentivizing(min_fee_rate);
        }

        if let Some((additional_fee_index, fee_available)) = self
            .psbt
            .unsigned_tx
            .output
            .clone()
            .into_iter()
            .enumerate()
            .find(|(_, txo)| payout_scripts.all(|script| script != txo.script_pubkey))
            .map(|(i, txo)| (i, txo.value))
        {
            let mut input_pairs = self.psbt.input_pairs();
            let first_input_pair = input_pairs.next().ok_or(InternalBuildSenderError::NoInputs)?;
            let mut input_weight = first_input_pair
                .expected_input_weight()
                .map_err(InternalBuildSenderError::InputWeight)?;
            for input_pair in input_pairs {
                // use cheapest default if mixed input types
                if input_pair.address_type()? != first_input_pair.address_type()? {
                    input_weight =
                        bitcoin::transaction::InputWeightPrediction::P2TR_KEY_NON_DEFAULT_SIGHASH.weight()
                    // Lengths of txid, index and sequence: (32, 4, 4).
                    + Weight::from_non_witness_data_size(32 + 4 + 4);
                    break;
                }
            }

            let recommended_additional_fee = min_fee_rate * input_weight;
            if fee_available < recommended_additional_fee {
                log::warn!("Insufficient funds to maintain specified minimum feerate.");
                return self.build_with_additional_fee(
                    fee_available,
                    Some(additional_fee_index),
                    min_fee_rate,
                    true,
                );
            }
            return self.build_with_additional_fee(
                recommended_additional_fee,
                Some(additional_fee_index),
                min_fee_rate,
                false,
            );
        }
        self.build_non_incentivizing(min_fee_rate)
    }

    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. If `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    ///
    /// `clamp_fee_contribution` decreases fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub fn build_with_additional_fee(
        mut self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
    ) -> Result<Sender, BuildSenderError> {
        self.fee_contribution = Some((max_fee_contribution, change_index));
        self.clamp_fee_contribution = clamp_fee_contribution;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        mut self,
        min_fee_rate: FeeRate,
    ) -> Result<Sender, BuildSenderError> {
        // since this is a builder, these should already be cleared
        // but we'll reset them to be sure
        self.fee_contribution = None;
        self.clamp_fee_contribution = false;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    fn build(self) -> Result<Sender, BuildSenderError> {
        let mut psbt =
            self.psbt.validate().map_err(InternalBuildSenderError::InconsistentOriginalPsbt)?;
        psbt.validate_input_utxos().map_err(InternalBuildSenderError::InvalidOriginalInput)?;
        let endpoint = self.uri.extras.endpoint.clone();
        let output_substitution =
            self.uri.extras.output_substitution.combine(self.output_substitution);
        let payee = self.uri.address.script_pubkey();

        check_single_payee(&psbt, &payee, self.uri.amount)?;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee,
            self.fee_contribution,
            self.clamp_fee_contribution,
        )?;
        clear_unneeded_fields(&mut psbt);

        Ok(Sender {
            psbt,
            endpoint,
            output_substitution,
            fee_contribution,
            payee,
            min_fee_rate: self.min_fee_rate,
        })
    }
}

/// A payjoin V1 sender, allowing the construction of a payjoin V1 request
/// and the resulting `V1Context`
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "v2", derive(serde::Serialize, serde::Deserialize))]
pub struct Sender {
    /// The original PSBT.
    pub(crate) psbt: Psbt,
    /// The endpoint in the Payjoin URI
    pub(crate) endpoint: Url,
    /// Whether the receiver is allowed to substitute original outputs.
    pub(crate) output_substitution: OutputSubstitution,
    /// (maxadditionalfeecontribution, additionalfeeoutputindex)
    pub(crate) fee_contribution: Option<AdditionalFeeContribution>,
    pub(crate) min_fee_rate: FeeRate,
    /// Script of the person being paid
    pub(crate) payee: ScriptBuf,
}

impl Sender {
    /// Extract serialized V1 Request and Context from a Payjoin Proposal
    pub fn extract_v1(&self) -> (Request, V1Context) {
        let url = serialize_url(
            self.endpoint.clone(),
            self.output_substitution,
            self.fee_contribution,
            self.min_fee_rate,
            "1", // payjoin version
        );
        let body = self.psbt.to_string().as_bytes().to_vec();
        (
            Request::new_v1(&url, &body),
            V1Context {
                psbt_context: PsbtContext {
                    original_psbt: self.psbt.clone(),
                    output_substitution: self.output_substitution,
                    fee_contribution: self.fee_contribution,
                    payee: self.payee.clone(),
                    min_fee_rate: self.min_fee_rate,
                },
            },
        )
    }

    /// The endpoint in the Payjoin URI
    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

/// Data required to validate the response.
///
/// This type is used to process a BIP78 response.
/// Call [`Self::process_response`] on it to continue the BIP78 flow.
#[derive(Debug, Clone)]
pub struct V1Context {
    psbt_context: PsbtContext,
}

impl V1Context {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP78 flow. If the response is
    /// valid you will get appropriate PSBT that you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: &mut impl std::io::Read,
    ) -> Result<Psbt, ResponseError> {
        let mut buf_reader = BufReader::with_capacity(MAX_CONTENT_LENGTH + 1, response);
        let buffer = buf_reader.fill_buf().map_err(InternalValidationError::Io)?;

        if buffer.len() > MAX_CONTENT_LENGTH {
            return Err(ResponseError::from(InternalValidationError::ContentTooLarge));
        }

        let res_str = std::str::from_utf8(buffer).map_err(|_| InternalValidationError::Parse)?;
        let proposal = Psbt::from_str(res_str).map_err(|_| ResponseError::parse(res_str))?;
        self.psbt_context.process_proposal(proposal).map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::FeeRate;
    use payjoin_test_utils::{BoxError, PARSED_ORIGINAL_PSBT};

    use super::*;
    use crate::error_codes::ErrorCode;
    use crate::send::error::{ResponseError, WellKnownError};
    use crate::send::test::create_psbt_context;
    use crate::{Uri, UriExt};

    const PJ_URI: &str =
        "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.02&pjos=0&pj=HTTPS://EXAMPLE.COM/";

    /// From the BIP-174 test vector
    const INVALID_PSBT: &str = "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA&#61;&#61;";

    /// From the BIP-78 test vector
    const PJ_PROPOSAL_PSBT: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcAAQEggIQeAAAAAAAXqRTI8sv5ymFHLIjkZNRrNXSEXZHY1YcBBxcWABRfgGZV5ZJMkgTC1RvlOU9L+e2iEAEIawJHMEQCIGe7e0DfJaVPRYEKWxddL2Pr0G37BoKz0lyNa02O2/tWAiB7ZVgBoF4s8MHocYWWmo4Q1cyV2wl7MX0azlqa8NBENAEhAmXWPPW0G3yE3HajBOb7gO7iKzHSmZ0o0w0iONowcV+tAAAA";

    fn create_v1_context() -> super::V1Context {
        let psbt_context = create_psbt_context().expect("failed to create context");
        super::V1Context { psbt_context }
    }

    #[test]
    fn test_build_recommended() -> Result<(), BoxError> {
        let sender = SenderBuilder::new(
            PARSED_ORIGINAL_PSBT.clone(),
            Uri::try_from(PJ_URI)
                .map_err(|e| format!("{e}"))?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| format!("{e}"))?,
        )
        .build_recommended(FeeRate::MIN);
        assert!(sender.is_ok(), "{:#?}", sender.err());
        Ok(())
    }

    #[test]
    fn handle_json_errors() {
        let ctx = create_v1_context();
        let known_json_error = serde_json::json!({
            "errorCode": "version-unsupported",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut known_json_error.as_bytes()) {
            Err(ResponseError::WellKnown(WellKnownError {
                code: ErrorCode::VersionUnsupported,
                ..
            })) => (),
            _ => panic!("Expected WellKnownError"),
        }

        let ctx = create_v1_context();
        let invalid_json_error = serde_json::json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut invalid_json_error.as_bytes()) {
            Err(ResponseError::Validation(_)) => (),
            _ => panic!("Expected unrecognized JSON error"),
        }
    }

    #[test]
    fn process_response_valid() {
        let mut cursor = std::io::Cursor::new(PJ_PROPOSAL_PSBT.as_bytes());

        let ctx = create_v1_context();
        let response = ctx.process_response(&mut cursor);
        assert!(response.is_ok())
    }

    #[test]
    fn process_response_invalid_psbt() {
        let mut cursor = std::io::Cursor::new(INVALID_PSBT.as_bytes());

        let ctx = create_v1_context();
        let response = ctx.process_response(&mut cursor);
        match response {
            Ok(_) => panic!("Invalid PSBT should have caused an error"),
            Err(error) => match error {
                ResponseError::Validation(e) => {
                    assert_eq!(
                        e.to_string(),
                        ValidationError::from(InternalValidationError::Parse).to_string()
                    );
                }
                _ => panic!("Unexpected error type"),
            },
        }
    }

    #[test]
    fn process_response_invalid_utf8() {
        // In UTF-8, 0xF0 represents the start of a 4-byte sequence, so 0xF0 by itself is invalid
        let invalid_utf8 = [0xF0];
        let mut cursor = std::io::Cursor::new(invalid_utf8);

        let ctx = create_v1_context();
        let response = ctx.process_response(&mut cursor);
        match response {
            Ok(_) => panic!("Invalid UTF-8 should have caused an error"),
            Err(error) => match error {
                ResponseError::Validation(e) => {
                    assert_eq!(
                        e.to_string(),
                        ValidationError::from(InternalValidationError::Parse).to_string()
                    );
                }
                _ => panic!("Unexpected error type"),
            },
        }
    }
}
