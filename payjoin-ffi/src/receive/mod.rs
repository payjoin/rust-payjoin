use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub use error::{
    Error, InputContributionError, JsonReply, OutputSubstitutionError, PsbtInputError,
    ReplyableError, SelectionError, SessionError,
};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::FeeRate;
use payjoin::persist::SessionPersister;

use crate::bitcoin_ffi::{Address, OutPoint, Script, TxOut};
pub use crate::error::{ImplementationError, SerdeJsonError};
use crate::ohttp::OhttpKeys;
use crate::receive::error::{PersistedError, ReplayError};
use crate::{ClientResponse, OutputSubstitution, Request};

pub mod error;
#[cfg(feature = "uniffi")]
pub mod uni;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionEvent(payjoin::receive::v2::SessionEvent);

impl From<payjoin::receive::v2::SessionEvent> for SessionEvent {
    fn from(event: payjoin::receive::v2::SessionEvent) -> Self { Self(event) }
}

impl From<SessionEvent> for payjoin::receive::v2::SessionEvent {
    fn from(event: SessionEvent) -> Self { event.0 }
}

pub struct ReceiverState<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    pub payjoin::receive::v2::ReceiverTypeState<P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<payjoin::receive::v2::ReceiverTypeState<P>> for ReceiverState<P>
{
    fn from(value: payjoin::receive::v2::ReceiverTypeState<P>) -> Self { Self(value) }
}

pub fn replay_receiver_event_log<P>(
    persister: &P,
) -> Result<(ReceiverState<P>, SessionHistory), ReplayError>
where
    P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone,
    P::SessionEvent: Into<payjoin::receive::v2::SessionEvent> + Clone,
{
    let (state, history) =
        payjoin::receive::v2::replay_receiver_event_log(persister).map_err(ReplayError::from)?;
    Ok((state.into(), history.into()))
}

#[derive(Default, Clone)]
pub struct SessionHistory(pub payjoin::receive::v2::SessionHistory);

impl From<payjoin::receive::v2::SessionHistory> for SessionHistory {
    fn from(value: payjoin::receive::v2::SessionHistory) -> Self { Self(value) }
}

pub struct UninitializedReceiver<
    P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>,
>(payjoin::receive::v2::Receiver<payjoin::receive::v2::UninitializedReceiver, P>);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<UninitializedReceiver<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::UninitializedReceiver, P>
{
    fn from(value: UninitializedReceiver<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::UninitializedReceiver, P>>
    for UninitializedReceiver<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::UninitializedReceiver, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    UninitializedReceiver<P>
{
    /// Creates a new [`WithContext`] with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `expire_after`: The duration after which the session expires.
    ///
    /// # Returns
    /// A new instance of [`WithContext`].
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
    pub fn create_session(
        address: Address,
        directory: String,
        ohttp_keys: OhttpKeys,
        expire_after: Option<u64>,
        persister: P,
    ) -> Result<WithContext<P>, PersistedError> {
        let res = payjoin::receive::v2::Receiver::create_session(
            address.into(),
            directory,
            ohttp_keys.into(),
            expire_after.map(Duration::from_secs),
            persister,
        )
        .map_err(|e| PersistedError::from(e))?;
        Ok(res.into())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WithContext<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>> From<WithContext<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>
{
    fn from(value: WithContext<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>> for WithContext<P>
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>) -> Self {
        Self(value)
    }
}

pub struct WithContextTransitionOutcome<
    P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>,
>(
    payjoin::persist::OptionalTransitionOutcome<
        payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>,
        payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>,
    >,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    WithContextTransitionOutcome<P>
{
    pub fn is_none(&self) -> bool { self.0.is_none() }

    pub fn is_success(&self) -> bool { self.0.is_success() }

    pub fn success(self) -> Option<UncheckedProposal<P>> {
        self.0.success().map(|r| UncheckedProposal(r))
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<
        payjoin::persist::OptionalTransitionOutcome<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>,
        >,
    > for WithContextTransitionOutcome<P>
{
    fn from(
        value: payjoin::persist::OptionalTransitionOutcome<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>,
        >,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    WithContext<P>
{
    pub fn extract_req(&self, ohttp_relay: String) -> Result<(Request, ClientResponse), Error> {
        self.0
            .clone()
            .extract_req(ohttp_relay)
            .map(|(req, ctx)| (req.into(), ctx.into()))
            .map_err(Into::into)
    }

    ///The response can either be an UncheckedProposal or an ACCEPTED message indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        body: &[u8],
        ctx: &ClientResponse,
    ) -> Result<WithContextTransitionOutcome<P>, PersistedError> {
        let res = self.0.process_res(body, ctx.into()).map_err(PersistedError::from)?;
        Ok(res.into())
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri(&self) -> crate::PjUri {
        <Self as Into<payjoin::receive::v2::Receiver<payjoin::receive::v2::WithContext, P>>>::into(
            self.clone(),
        )
        .pj_uri()
        .into()
    }
}

#[derive(Clone)]
pub struct UncheckedProposal<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>>
    for UncheckedProposal<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<UncheckedProposal<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedProposal, P>
{
    fn from(value: UncheckedProposal<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    UncheckedProposal<P>
{
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: impl Fn(&Vec<u8>) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsOwned<P>, PersistedError> {
        let res = self
            .0
            .clone()
            .check_broadcast_suitability(
                min_fee_rate.map(FeeRate::from_sat_per_kwu),
                |transaction| {
                    Ok(can_broadcast(&payjoin::bitcoin::consensus::encode::serialize(transaction))?)
                },
            )
            .map_err(PersistedError::from)?;

        Ok(res.into())
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> Result<MaybeInputsOwned<P>, PersistedError> {
        let res = self.clone().0.assume_interactive_receiver().map_err(|e| {
            PersistedError::Storage(Arc::new(ImplementationError::from(e.to_string())))
        })?;
        Ok(res.into())
    }
}

/// Process an OHTTP Encapsulated HTTP POST Error response
/// to ensure it has been posted properly
pub fn process_err_res(body: &[u8], context: &ClientResponse) -> Result<(), SessionError> {
    payjoin::receive::v2::process_err_res(body, context.into()).map_err(Into::into)
}
#[derive(Clone)]
pub struct MaybeInputsOwned<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned, P>>
    for MaybeInputsOwned<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    MaybeInputsOwned<P>
{
    pub fn check_inputs_not_owned(
        &self,
        is_owned: impl Fn(&Vec<u8>) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsSeen<P>, PersistedError> {
        let res = self
            .0
            .clone()
            .check_inputs_not_owned(|input| Ok(is_owned(&input.to_bytes())?))
            .map_err(PersistedError::from)?;
        Ok(res.into())
    }
}

#[derive(Clone)]
pub struct MaybeInputsSeen<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen, P>>
    for MaybeInputsSeen<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    MaybeInputsSeen<P>
{
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<OutputsUnknown<P>, PersistedError> {
        let res = self
            .0
            .clone()
            .check_no_inputs_seen_before(|outpoint| Ok(is_known(&(*outpoint).into())?))
            .map_err(PersistedError::from)?;
        Ok(res.into())
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Clone)]
pub struct OutputsUnknown<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown, P>>
    for OutputsUnknown<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<OutputsUnknown<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown, P>
{
    fn from(value: OutputsUnknown<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    OutputsUnknown<P>
{
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: impl Fn(&Vec<u8>) -> Result<bool, ImplementationError>,
    ) -> Result<WantsOutputs<P>, PersistedError> {
        let res = self
            .0
            .clone()
            .identify_receiver_outputs(|input| Ok(is_receiver_output(&input.to_bytes())?))
            .map_err(PersistedError::from)?;
        Ok(res.into())
    }
}

pub struct WantsOutputs<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs, P>>
    for WantsOutputs<P>
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs, P>) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<WantsOutputs<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs, P>
{
    fn from(value: WantsOutputs<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    WantsOutputs<P>
{
    pub fn output_substitution(&self) -> OutputSubstitution { self.0.output_substitution() }

    pub fn replace_receiver_outputs(
        &self,
        replacement_outputs: Vec<TxOut>,
        drain_script: &Script,
    ) -> Result<WantsOutputs<P>, OutputSubstitutionError> {
        let replacement_outputs: Vec<payjoin::bitcoin::TxOut> =
            replacement_outputs.iter().map(|o| o.clone().into()).collect();
        self.0
            .clone()
            .replace_receiver_outputs(replacement_outputs, &drain_script.0)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn substitute_receiver_script(
        &self,
        output_script: &Script,
    ) -> Result<WantsOutputs<P>, OutputSubstitutionError> {
        self.0
            .clone()
            .substitute_receiver_script(&output_script.0)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_outputs(&self) -> Result<WantsInputs<P>, PersistedError> {
        let res = self.0.clone().commit_outputs().map_err(|e| {
            PersistedError::Storage(Arc::new(ImplementationError::from(e.to_string())))
        })?;
        Ok(res.into())
    }
}

pub struct WantsInputs<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs, P>> for WantsInputs<P>
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs, P>) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<WantsInputs<P>> for payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs, P>
{
    fn from(value: WantsInputs<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    WantsInputs<P>
{
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    // if min(out) < min(in) then UIH1 else UIH2
    // https://eprint.iacr.org/2022/589.pdf
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: Vec<InputPair>,
    ) -> Result<InputPair, SelectionError> {
        match self.0.clone().try_preserving_privacy(candidate_inputs.into_iter().map(Into::into)) {
            Ok(t) => Ok(t.into()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contribute_inputs(
        &self,
        replacement_inputs: Vec<InputPair>,
    ) -> Result<WantsInputs<P>, InputContributionError> {
        self.0
            .clone()
            .contribute_inputs(replacement_inputs.into_iter().map(Into::into))
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_inputs(&self) -> Result<ProvisionalProposal<P>, PersistedError> {
        let res = self.0.clone().commit_inputs().map_err(|e| {
            PersistedError::Storage(Arc::new(ImplementationError::from(e.to_string())))
        })?;
        Ok(res.into())
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct InputPair(payjoin::receive::InputPair);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl InputPair {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(
        txin: bitcoin_ffi::TxIn,
        psbtin: crate::bitcoin_ffi::PsbtInput,
    ) -> Result<Self, PsbtInputError> {
        Ok(Self(payjoin::receive::InputPair::new(txin.into(), psbtin.into())?))
    }
}

impl From<InputPair> for payjoin::receive::InputPair {
    fn from(value: InputPair) -> Self { value.0 }
}

impl From<payjoin::receive::InputPair> for InputPair {
    fn from(value: payjoin::receive::InputPair) -> Self { Self(value) }
}

pub struct ProvisionalProposal<
    P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>,
>(pub payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal, P>);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal, P>>
    for ProvisionalProposal<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    ProvisionalProposal<P>
{
    pub fn finalize_proposal(
        &self,
        process_psbt: impl Fn(String) -> Result<String, ImplementationError>,
        min_feerate_sat_per_vb: Option<u64>,
        max_effective_fee_rate_sat_per_vb: Option<u64>,
    ) -> Result<PayjoinProposal<P>, PersistedError> {
        let res = self
            .0
            .clone()
            .finalize_proposal(
                |pre_processed| {
                    let psbt = process_psbt(pre_processed.to_string())?;
                    Ok(Psbt::from_str(&psbt)?)
                },
                min_feerate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
                max_effective_fee_rate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
            )
            .map_err(PersistedError::from)?;
        Ok(res.into())
    }
}

#[derive(Clone)]
pub struct PayjoinProposal<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent>>(
    pub payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>,
);

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>>
    for PayjoinProposal<P>
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>,
    ) -> Self {
        Self(value)
    }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    From<PayjoinProposal<P>>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>
{
    fn from(value: PayjoinProposal<P>) -> Self { value.0 }
}

impl<P: SessionPersister<SessionEvent = payjoin::receive::v2::SessionEvent> + Clone>
    PayjoinProposal<P>
{
    pub fn utxos_to_be_locked(&self) -> Vec<OutPoint> {
        let mut outpoints: Vec<OutPoint> = Vec::new();
        for o in <PayjoinProposal<P> as Into<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>,
        >>::into(self.clone())
        .utxos_to_be_locked()
        {
            outpoints.push((*o).into());
        }
        outpoints
    }

    pub fn psbt(&self) -> String {
        <PayjoinProposal<P> as Into<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal, P>,
        >>::into(self.clone())
        .psbt()
        .clone()
        .to_string()
    }

    /// Extract an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn extract_req(&self, ohttp_relay: String) -> Result<(Request, ClientResponse), Error> {
        self.0
            .clone()
            .extract_req(ohttp_relay)
            .map_err(Into::into)
            .map(|(req, ctx)| (req.into(), ctx.into()))
    }

    ///Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful, it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        body: &[u8],
        ohttp_context: &ClientResponse,
    ) -> Result<(), PersistedError> {
        self.0.clone().process_res(body, ohttp_context.into()).map_err(PersistedError::from)?;
        Ok(())
    }
}

// #[cfg(test)]
// #[cfg(not(feature = "uniffi"))]
// mod test {
//     use std::sync::Arc;

//     use super::*;

//     fn get_proposal_from_test_vector() -> Result<UncheckedProposal, Error> {
//         // OriginalPSBT Test Vector from BIP
//         // | InputScriptType | Original PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
//         // |-----------------|------------------------|------------------------------|-------------------------|
//         // | P2SH-P2WPKH     |  2 sat/vbyte           | 0.00000182                   | 0                       |
//         let original_psbt =
//             "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
//         let body = original_psbt.as_bytes();

//         let headers = Headers::from_vec(body.to_vec());
//         UncheckedProposal::from_request(
//             body.to_vec(),
//             "?maxadditionalfeecontribution=182?additionalfeeoutputindex=0".to_string(),
//             Arc::new(headers),
//         )
//     }

//     #[test]
//     fn can_get_proposal_from_request() {
//         let proposal = get_proposal_from_test_vector();
//         assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
//     }

//     #[test]
//     fn unchecked_proposal_unlocks_after_checks() {
//         let proposal = get_proposal_from_test_vector().unwrap();
//         let _payjoin = proposal
//             .assume_interactive_receiver()
//             .clone()
//             .check_inputs_not_owned(|_| Ok(true))
//             .expect("No inputs should be owned")
//             .check_no_inputs_seen_before(|_| Ok(false))
//             .expect("No inputs should be seen before")
//             .identify_receiver_outputs(|script| {
//                 let network = payjoin::bitcoin::Network::Bitcoin;
//                 let script = payjoin::bitcoin::ScriptBuf::from_bytes(script.to_vec());
//                 Ok(payjoin::bitcoin::Address::from_script(&script, network).unwrap()
//                     == payjoin::bitcoin::Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
//                         .map(|x| x.require_network(network).unwrap())
//                         .unwrap())
//             })
//             .expect("Receiver output should be identified");
//     }
// }
