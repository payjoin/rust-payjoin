use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use super::InputPair;
use crate::bitcoin_ffi::{Address, OutPoint, Script, TxOut};
use crate::error::ForeignError;
use crate::receive::error::{PersistedError, ReplayError};
pub use crate::receive::{
    Error, ImplementationError, InputContributionError, JsonReply, OutputSubstitutionError,
    ReplyableError, SelectionError, SerdeJsonError, SessionError,
};
use crate::{ClientResponse, OhttpKeys, OutputSubstitution, Request};

#[derive(Clone, uniffi::Object, serde::Serialize, serde::Deserialize)]
pub struct SessionEvent(super::SessionEvent);

impl From<SessionEvent> for super::SessionEvent {
    fn from(value: SessionEvent) -> Self { value.0 }
}

impl From<super::SessionEvent> for SessionEvent {
    fn from(value: super::SessionEvent) -> Self { SessionEvent(value) }
}

#[uniffi::export]
impl SessionEvent {
    pub fn to_json(&self) -> Result<String, SerdeJsonError> {
        serde_json::to_string(&self.0).map_err(Into::into)
    }

    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, SerdeJsonError> {
        let event: payjoin::receive::v2::SessionEvent = serde_json::from_str(&json)?;
        Ok(SessionEvent(event.into()))
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum ReceiverState {
    Uninitialized,
    WithContext { inner: Arc<WithContext> },
    UncheckedProposal { inner: Arc<UncheckedProposal> },
    MaybeInputsOwned { inner: Arc<MaybeInputsOwned> },
    MaybeInputsSeen { inner: Arc<MaybeInputsSeen> },
    OutputsUnknown { inner: Arc<OutputsUnknown> },
    WantsOutputs { inner: Arc<WantsOutputs> },
    WantsInputs { inner: Arc<WantsInputs> },
    ProvisionalProposal { inner: Arc<ProvisionalProposal> },
    PayjoinProposal { inner: Arc<PayjoinProposal> },
    TerminalState,
}

impl From<super::ReceiverState<CallbackPersisterAdapter>> for ReceiverState {
    fn from(value: super::ReceiverState<CallbackPersisterAdapter>) -> Self {
        use payjoin::receive::v2::ReceiverTypeState::*;
        match value.0 {
            Uninitialized(_) => Self::Uninitialized,
            WithContext(inner) =>
                Self::WithContext { inner: Arc::new(super::WithContext::from(inner).into()) },
            UncheckedProposal(inner) => Self::UncheckedProposal {
                inner: Arc::new(super::UncheckedProposal::from(inner).into()),
            },
            MaybeInputsOwned(inner) => Self::MaybeInputsOwned {
                inner: Arc::new(super::MaybeInputsOwned::from(inner).into()),
            },
            MaybeInputsSeen(inner) => Self::MaybeInputsSeen {
                inner: Arc::new(super::MaybeInputsSeen::from(inner).into()),
            },
            OutputsUnknown(inner) =>
                Self::OutputsUnknown { inner: Arc::new(super::OutputsUnknown::from(inner).into()) },
            WantsOutputs(inner) =>
                Self::WantsOutputs { inner: Arc::new(super::WantsOutputs::from(inner).into()) },
            WantsInputs(inner) =>
                Self::WantsInputs { inner: Arc::new(super::WantsInputs::from(inner).into()) },
            ProvisionalProposal(inner) => Self::ProvisionalProposal {
                inner: Arc::new(super::ProvisionalProposal::from(inner).into()),
            },
            PayjoinProposal(inner) => Self::PayjoinProposal {
                inner: Arc::new(super::PayjoinProposal::from(inner).into()),
            },
            TerminalState => Self::TerminalState,
        }
    }
}
#[derive(uniffi::Object, Clone)]
pub struct SessionHistory(super::SessionHistory);

impl From<super::SessionHistory> for SessionHistory {
    fn from(value: super::SessionHistory) -> Self { Self(value) }
}

impl From<SessionHistory> for super::SessionHistory {
    fn from(value: SessionHistory) -> Self { value.0 }
}

#[derive(uniffi::Object)]
pub struct TerminalError {
    error: String,
    reply: Option<JsonReply>,
}

#[uniffi::export]
impl TerminalError {
    pub fn error(&self) -> String { self.error.clone() }

    pub fn reply(&self) -> Option<Arc<JsonReply>> {
        self.reply.clone().map(|reply| Arc::new(reply))
    }
}

#[uniffi::export]
impl SessionHistory {
    /// Receiver session Payjoin URI
    pub fn pj_uri(&self) -> Option<Arc<crate::PjUri>> {
        self.0 .0.pj_uri().map(|pj_uri| Arc::new(pj_uri.into()))
    }

    /// Payment amount from the Payjoin URI
    pub fn pj_uri_amount(&self) -> Option<u64> {
        self.0 .0.pj_uri_amount().map(|amount| amount.to_sat())
    }

    /// Payment address from the Payjoin URI
    pub fn payment_address(&self) -> Option<Arc<crate::Address>> {
        self.0 .0.payment_address().map(|address| Arc::new(address.into()))
    }

    /// Fallback tx from the original proposal
    pub fn original_psbt(&self) -> Option<Arc<crate::Psbt>> {
        self.0 .0.original_psbt().map(|psbt| Arc::new(psbt.into()))
    }

    /// Fallback tx from the original proposal
    pub fn fallback_tx(
        &self,
    ) -> Result<Option<Arc<crate::Transaction>>, bitcoin_ffi::error::ExtractTxError> {
        // TODO: this clone could be replaced with interior mutability
        let self_clone = self.clone();
        let fallback = self_clone.0 .0.fallback_tx();
        match fallback {
            Some(tx) => match tx {
                Ok(tx) => Ok(Some(Arc::new(tx.into()))),
                Err(e) => return Err(e.into()),
            },
            None => Ok(None),
        }
    }

    /// Proposed payjoin psbt from the payjoin proposal
    pub fn proposed_payjoin_psbt(&self) -> Option<Arc<crate::Psbt>> {
        self.0 .0.proposed_payjoin_psbt().map(|psbt| Arc::new(psbt.into()))
    }

    /// Psbt with receiver contributed inputs
    pub fn psbt_with_contributed_inputs(&self) -> Option<Arc<crate::Psbt>> {
        self.0 .0.psbt_with_contributed_inputs().map(|psbt| Arc::new(psbt.into()))
    }

    /// Terminal error from the session if present
    pub fn terminal_error(&self) -> Option<Arc<TerminalError>> {
        self.0 .0.terminal_error().map(|(error, reply)| {
            Arc::new(TerminalError { error, reply: reply.map(|reply| reply.into()) })
        })
    }

    /// Extract the error request to be posted on the directory if an error occurred.
    /// To process the response, use [process_err_res]
    pub fn extract_err_req(
        &self,
        ohttp_relay: String,
    ) -> Result<Option<RequestResponse>, SessionError> {
        match self.0 .0.extract_err_req(ohttp_relay) {
            Ok(Some((request, ctx))) => Ok(Some(RequestResponse {
                request: request.into(),
                client_response: Arc::new(ctx.into()),
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(SessionError::from(e)),
        }
    }
}

#[derive(uniffi::Object)]
pub struct ReplayResult {
    state: ReceiverState,
    session_history: SessionHistory,
}

#[uniffi::export]
impl ReplayResult {
    pub fn state(&self) -> ReceiverState { self.state.clone() }

    pub fn session_history(&self) -> SessionHistory { self.session_history.clone() }
}

#[uniffi::export]
pub fn replay_receiver_event_log(
    persister: Arc<dyn JsonReceiverSessionPersister>,
) -> Result<ReplayResult, ReplayError> {
    let adapter = CallbackPersisterAdapter::new(persister);
    let (state, session_history) =
        super::replay_receiver_event_log(&adapter).map_err(ReplayError::from)?;
    Ok(ReplayResult { state: state.into(), session_history: session_history.into() })
}

#[derive(uniffi::Object)]
pub struct UninitializedReceiver {}

impl From<super::UninitializedReceiver<CallbackPersisterAdapter>> for UninitializedReceiver {
    fn from(_: super::UninitializedReceiver<CallbackPersisterAdapter>) -> Self { Self {} }
}

#[uniffi::export]
impl UninitializedReceiver {
    #[uniffi::constructor]
    // TODO: no need for this constructor. `create_session` is the only way to create a receiver.
    pub fn new() -> Self { Self {} }

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
        &self,
        address: Arc<Address>,
        directory: String,
        ohttp_keys: Arc<OhttpKeys>,
        expire_after: Option<u64>,
        session_persister: Arc<dyn JsonReceiverSessionPersister>,
    ) -> Result<WithContext, PersistedError> {
        let adapter = CallbackPersisterAdapter::new(session_persister);
        let res = super::UninitializedReceiver::create_session(
            (*address).clone(),
            directory,
            (*ohttp_keys).clone(),
            expire_after,
            adapter,
        )?;
        Ok(res.into())
    }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct WithContext(Arc<RwLock<super::WithContext<CallbackPersisterAdapter>>>);

impl From<WithContext> for super::WithContext<CallbackPersisterAdapter> {
    fn from(value: WithContext) -> Self { value.0.read().unwrap().clone() }
}

impl From<super::WithContext<CallbackPersisterAdapter>> for WithContext {
    fn from(value: super::WithContext<CallbackPersisterAdapter>) -> Self {
        Self(Arc::new(RwLock::new(value)))
    }
}

#[derive(uniffi::Object)]
pub struct WithContextTransitionOutcome(
    Arc<RwLock<Option<super::WithContextTransitionOutcome<CallbackPersisterAdapter>>>>,
);

impl From<super::WithContextTransitionOutcome<CallbackPersisterAdapter>>
    for WithContextTransitionOutcome
{
    fn from(value: super::WithContextTransitionOutcome<CallbackPersisterAdapter>) -> Self {
        Self(Arc::new(RwLock::new(Some(value))))
    }
}

#[uniffi::export]
impl WithContextTransitionOutcome {
    pub fn success(&self) -> Option<Arc<UncheckedProposal>> {
       let mut inner =
            self.0.write().unwrap();

        let value = inner
            .take()
            .unwrap();
        value.success().map(|p| Arc::new(UncheckedProposal(p.into())))
    }
}

#[uniffi::export]
impl WithContext {
    /// The contents of the `&pj=` query parameter including the base64url-encoded public key receiver subdirectory.
    /// This identifies a session at the payjoin directory server.
    pub fn pj_uri(&self) -> crate::PjUri { self.0.read().unwrap().pj_uri() }

    pub fn extract_req(&self, ohttp_relay: String) -> Result<RequestResponse, Error> {
        self.0
            .read()
            .unwrap()
            .extract_req(ohttp_relay)
            .map(|(request, ctx)| RequestResponse { request, client_response: Arc::new(ctx) })
    }

    ///The response can either be an UncheckedProposal or an ACCEPTED message indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &self,
        body: &[u8],
        context: Arc<ClientResponse>,
    ) -> Result<WithContextTransitionOutcome, PersistedError> {
        // TODO: what we probably want is support persisterError in this ffi crate and write to and from methods
        let mut inner = self.0.write().expect("Lock should not be poisoned");
        let res = inner
            .process_res(body, &context)?;
        Ok(res.into())
    }
}

#[derive(uniffi::Record)]
pub struct RequestResponse {
    pub request: Request,
    pub client_response: Arc<ClientResponse>,
}

#[uniffi::export(with_foreign)]
pub trait CanBroadcast: Send + Sync {
    fn callback(&self, tx: Vec<u8>) -> Result<bool, ForeignError>;
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to process the request. It is returned by UncheckedProposal::from_request().
///
/// If you are implementing an interactive payment processor, you should get extract the original transaction with get_transaction_to_schedule_broadcast() and schedule, followed by checking that the transaction can be broadcast with check_can_broadcast. Otherwise it is safe to call assume_interactive_receive to proceed with validation.
#[derive(Clone, uniffi::Object)]
pub struct UncheckedProposal(super::UncheckedProposal<CallbackPersisterAdapter>);

impl From<super::UncheckedProposal<CallbackPersisterAdapter>> for UncheckedProposal {
    fn from(value: super::UncheckedProposal<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl UncheckedProposal {
    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender can be broadcast, i.e. testmempoolaccept bitcoind rpc returns { "allowed": true,.. } for get_transaction_to_check_broadcast() before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor. Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks. If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost. Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: Arc<dyn CanBroadcast>,
    ) -> Result<MaybeInputsOwned, PersistedError> {
        let res = self
            .0
            .check_broadcast_suitability(min_fee_rate, |transaction| {
                can_broadcast
                    .callback(transaction.to_vec())
                    .map_err(|e| ImplementationError::from(e.to_string()))
            })?;
        Ok(res.into())
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> Result<MaybeInputsOwned, PersistedError> {
        let res = self.0.assume_interactive_receiver()?;
        Ok(res.into())
    }
}

/// Process an OHTTP Encapsulated HTTP POST Error response
/// to ensure it has been posted properly
#[uniffi::export]
pub fn process_err_res(body: &[u8], context: Arc<ClientResponse>) -> Result<(), SessionError> {
    super::process_err_res(body, &context)
}

/// Type state to validate that the Original PSBT has no receiver-owned inputs.
/// Call check_no_receiver_owned_inputs() to proceed.
#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsOwned(super::MaybeInputsOwned<CallbackPersisterAdapter>);

impl From<super::MaybeInputsOwned<CallbackPersisterAdapter>> for MaybeInputsOwned {
    fn from(value: super::MaybeInputsOwned<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export(with_foreign)]
pub trait IsScriptOwned: Send + Sync {
    fn callback(&self, script: Vec<u8>) -> Result<bool, ForeignError>;
}

#[uniffi::export]
impl MaybeInputsOwned {
    ///Check that the Original PSBT has no receiver-owned inputs. Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Arc<dyn IsScriptOwned>,
    ) -> Result<MaybeInputsSeen, PersistedError> {
        let res = self
            .0
            .check_inputs_not_owned(|input| {
                is_owned
                    .callback(input.to_vec())
                    .map_err(|e| ImplementationError::from(e.to_string()))
            })?;
        Ok(res.into())
    }
}

#[uniffi::export(with_foreign)]
pub trait IsOutputKnown: Send + Sync {
    fn callback(&self, outpoint: OutPoint) -> Result<bool, ForeignError>;
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call check_no_inputs_seen to proceed.
#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsSeen(super::MaybeInputsSeen<CallbackPersisterAdapter>);

impl From<super::MaybeInputsSeen<CallbackPersisterAdapter>> for MaybeInputsSeen {
    fn from(value: super::MaybeInputsSeen<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before. This prevents probing attacks. This prevents reentrant Payjoin, where a sender proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Arc<dyn IsOutputKnown>,
    ) -> Result<OutputsUnknown, PersistedError> {
        let res = self
            .0
            .check_no_inputs_seen_before(|outpoint| {
                is_known
                    .callback(outpoint.clone())
                    .map_err(|e| ImplementationError::from(e.to_string()))
            })?;
        Ok(res.into())
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money. Identify those outputs with identify_receiver_outputs() to proceed
#[derive(Clone, uniffi::Object)]
pub struct OutputsUnknown(super::OutputsUnknown<CallbackPersisterAdapter>);

impl From<super::OutputsUnknown<CallbackPersisterAdapter>> for OutputsUnknown {
    fn from(value: super::OutputsUnknown<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: Arc<dyn IsScriptOwned>,
    ) -> Result<WantsOutputs, PersistedError> {
        let res = self
            .0
            .identify_receiver_outputs(|output_script| {
                is_receiver_output
                    .callback(output_script.to_vec())
                    .map_err(|e| ImplementationError::from(e.to_string()))
            })?;
        Ok(res.into())
    }
}

#[derive(uniffi::Object)]
pub struct WantsOutputs(super::WantsOutputs<CallbackPersisterAdapter>);

impl From<super::WantsOutputs<CallbackPersisterAdapter>> for WantsOutputs {
    fn from(value: super::WantsOutputs<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl WantsOutputs {
    pub fn output_substitution(&self) -> OutputSubstitution { self.0.output_substitution() }

    pub fn replace_receiver_outputs(
        &self,
        replacement_outputs: Vec<TxOut>,
        drain_script: Arc<Script>,
    ) -> Result<Arc<WantsOutputs>, OutputSubstitutionError> {
        self.0
            .replace_receiver_outputs(replacement_outputs, &drain_script)
            .map(|t| Arc::new(t.into()))
    }

    pub fn commit_outputs(&self) -> Result<WantsInputs, PersistedError> {
        let res = self.0.commit_outputs()?;
        Ok(res.into())
    }

    pub fn substitute_receiver_script(
        &self,
        output_script: Arc<Script>,
    ) -> Result<Arc<WantsOutputs>, OutputSubstitutionError> {
        self.0.substitute_receiver_script(&output_script).map(|t| Arc::new(t.into()))
    }
}

#[derive(uniffi::Object)]
pub struct WantsInputs(super::WantsInputs<CallbackPersisterAdapter>);

impl From<super::WantsInputs<CallbackPersisterAdapter>> for WantsInputs {
    fn from(value: super::WantsInputs<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl WantsInputs {
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
        candidate_inputs: Vec<Arc<InputPair>>,
    ) -> Result<Arc<InputPair>, SelectionError> {
        let candidate_inputs: Vec<InputPair> = candidate_inputs
            .into_iter()
            .map(|pair| Arc::try_unwrap(pair).unwrap_or_else(|arc| (*arc).clone()))
            .collect();

        self.0.try_preserving_privacy(candidate_inputs).map(Arc::new)
    }

    pub fn contribute_inputs(
        &self,
        replacement_inputs: Vec<Arc<InputPair>>,
    ) -> Result<Arc<WantsInputs>, InputContributionError> {
        let replacement_inputs: Vec<InputPair> = replacement_inputs
            .into_iter()
            .map(|pair| Arc::try_unwrap(pair).unwrap_or_else(|arc| (*arc).clone()))
            .collect();
        self.0.contribute_inputs(replacement_inputs).map(|t| Arc::new(t.into()))
    }

    pub fn commit_inputs(&self) -> Result<ProvisionalProposal, PersistedError> {
        let res = self.0.commit_inputs()?;
        Ok(res.into())
    }
}

#[derive(uniffi::Object)]
pub struct ProvisionalProposal(super::ProvisionalProposal<CallbackPersisterAdapter>);

impl From<super::ProvisionalProposal<CallbackPersisterAdapter>> for ProvisionalProposal {
    fn from(value: super::ProvisionalProposal<CallbackPersisterAdapter>) -> Self { Self(value) }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[uniffi::export]
impl ProvisionalProposal {
    pub fn finalize_proposal(
        &self,
        process_psbt: Arc<dyn ProcessPsbt>,
        min_feerate_sat_per_vb: Option<u64>,
        max_effective_fee_rate_sat_per_vb: Option<u64>,
    ) -> Result<PayjoinProposal, PersistedError> {
        let res = self
            .0
            .finalize_proposal(
                |psbt| {
                    process_psbt
                        .callback(psbt.to_string())
                        .map_err(|e| ImplementationError::from(e.to_string()))
                },
                min_feerate_sat_per_vb,
                max_effective_fee_rate_sat_per_vb,
            )?;
        Ok(res.into())
    }
}

#[uniffi::export(with_foreign)]
pub trait ProcessPsbt: Send + Sync {
    fn callback(&self, psbt: String) -> Result<String, ForeignError>;
}

#[derive(Clone, uniffi::Object)]
pub struct PayjoinProposal(super::PayjoinProposal<CallbackPersisterAdapter>);

impl From<PayjoinProposal> for super::PayjoinProposal<CallbackPersisterAdapter> {
    fn from(value: PayjoinProposal) -> Self { value.0 }
}

impl From<super::PayjoinProposal<CallbackPersisterAdapter>> for PayjoinProposal {
    fn from(value: super::PayjoinProposal<CallbackPersisterAdapter>) -> Self { Self(value) }
}

#[uniffi::export]
impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> Vec<crate::OutPoint> {
        let mut outpoints: Vec<crate::OutPoint> = Vec::new();
        for e in <PayjoinProposal as Into<super::PayjoinProposal<CallbackPersisterAdapter>>>::into(
            self.clone(),
        )
        .utxos_to_be_locked()
        {
            outpoints.push(e.to_owned());
        }
        outpoints
    }

    pub fn psbt(&self) -> String { self.0.psbt() }

    /// Extract an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn extract_req(&self, ohttp_relay: String) -> Result<RequestResponse, Error> {
        let (req, res) = self.0.extract_req(ohttp_relay)?;
        Ok(RequestResponse { request: req, client_response: Arc::new(res) })
    }

    ///Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful, it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        body: &[u8],
        ctx: Arc<ClientResponse>,
    ) -> Result<(), PersistedError> {
        self.0
            .process_res(body, ctx.as_ref())?;
        Ok(())
    }
}

/// Session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
pub trait JsonReceiverSessionPersister: Send + Sync + Debug {
    fn save(&self, event: String) -> Result<(), ForeignError>;
    fn load(&self) -> Result<Vec<String>, ForeignError>;
    fn close(&self) -> Result<(), ForeignError>;
}

/// Adapter for the [JsonReceiverSessionPersister] trait to use the save and load callbacks.
#[derive(Clone, Debug)]
struct CallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonReceiverSessionPersister>,
}

impl CallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonReceiverSessionPersister>) -> Self {
        Self { callback_persister }
    }
}

impl payjoin::persist::SessionPersister for CallbackPersisterAdapter {
    type SessionEvent = payjoin::receive::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let super_event: super::SessionEvent = event.clone().into();
        let uni_event: SessionEvent = super_event.into();
        self.callback_persister
            .save(uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?)
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let res = self.callback_persister.load()?;
        Ok(Box::new(
            match res
                .into_iter()
                .map(|event| {
                    SessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(|e| e.0.into())
                })
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(events) => Box::new(events.into_iter()),
                Err(e) => return Err(e),
            },
        ))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { self.callback_persister.close() }
}
