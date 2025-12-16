use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub use error::{
    AddressParseError, InputContributionError, InputPairError, JsonReply, OutputSubstitutionError,
    ProtocolError, PsbtInputError, ReceiverBuilderError, ReceiverError, SelectionError,
    SessionError,
};
use payjoin::bitcoin::consensus::Decodable;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::{MaybeFatalTransition, NextStateTransition};

use crate::error::ForeignError;
pub use crate::error::{ImplementationError, SerdeJsonError};
use crate::ohttp::OhttpKeys;
use crate::receive::error::{ReceiverPersistedError, ReceiverReplayError};
use crate::uri::error::PayjoinFeeRateError;
use crate::{ClientResponse, OutputSubstitution, Request};

pub mod error;

macro_rules! impl_save_for_transition {
    ($ty:ident, $next_state:ident) => {
        #[uniffi::export]
        impl $ty {
            pub fn save(
                &self,
                persister: Arc<dyn JsonReceiverSessionPersister>,
            ) -> Result<$next_state, ReceiverPersistedError> {
                let adapter = CallbackPersisterAdapter::new(persister);
                let mut inner = self.0.write().expect("Lock should not be poisoned");

                let value = inner.take().expect("Already saved or moved");

                let res = value
                    .save(&adapter)
                    .map_err(|e| ReceiverPersistedError::from(ImplementationError::new(e)))?;
                Ok(res.into())
            }
        }
    };
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Object)]
pub struct ReceiverSessionEvent(payjoin::receive::v2::SessionEvent);

impl From<payjoin::receive::v2::SessionEvent> for ReceiverSessionEvent {
    fn from(event: payjoin::receive::v2::SessionEvent) -> Self { Self(event) }
}

impl From<ReceiverSessionEvent> for payjoin::receive::v2::SessionEvent {
    fn from(event: ReceiverSessionEvent) -> Self { event.0 }
}

#[uniffi::export]
impl ReceiverSessionEvent {
    pub fn to_json(&self) -> Result<String, SerdeJsonError> {
        serde_json::to_string(&self.0).map_err(Into::into)
    }

    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, SerdeJsonError> {
        let event: payjoin::receive::v2::SessionEvent = serde_json::from_str(&json)?;
        Ok(ReceiverSessionEvent(event))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct ReceiverSessionOutcome {
    inner: payjoin::receive::v2::SessionOutcome,
}

impl From<payjoin::receive::v2::SessionOutcome> for ReceiverSessionOutcome {
    fn from(value: payjoin::receive::v2::SessionOutcome) -> Self { Self { inner: value } }
}

impl From<ReceiverSessionOutcome> for payjoin::receive::v2::SessionOutcome {
    fn from(value: ReceiverSessionOutcome) -> Self { value.inner }
}

#[derive(Clone, uniffi::Enum)]
pub enum ReceiveSession {
    Initialized { inner: Arc<Initialized> },
    UncheckedOriginalPayload { inner: Arc<UncheckedOriginalPayload> },
    MaybeInputsOwned { inner: Arc<MaybeInputsOwned> },
    MaybeInputsSeen { inner: Arc<MaybeInputsSeen> },
    OutputsUnknown { inner: Arc<OutputsUnknown> },
    WantsOutputs { inner: Arc<WantsOutputs> },
    WantsInputs { inner: Arc<WantsInputs> },
    WantsFeeRange { inner: Arc<WantsFeeRange> },
    ProvisionalProposal { inner: Arc<ProvisionalProposal> },
    PayjoinProposal { inner: Arc<PayjoinProposal> },
    HasReplyableError { inner: Arc<HasReplyableError> },
    Monitor { inner: Arc<Monitor> },
    Closed { inner: Arc<ReceiverSessionOutcome> },
}

impl From<payjoin::receive::v2::ReceiveSession> for ReceiveSession {
    fn from(value: payjoin::receive::v2::ReceiveSession) -> Self {
        use payjoin::receive::v2::ReceiveSession;
        match value {
            ReceiveSession::Initialized(inner) =>
                Self::Initialized { inner: Arc::new(inner.into()) },
            ReceiveSession::UncheckedOriginalPayload(inner) =>
                Self::UncheckedOriginalPayload { inner: Arc::new(inner.into()) },
            ReceiveSession::MaybeInputsOwned(inner) =>
                Self::MaybeInputsOwned { inner: Arc::new(inner.into()) },
            ReceiveSession::MaybeInputsSeen(inner) =>
                Self::MaybeInputsSeen { inner: Arc::new(inner.into()) },
            ReceiveSession::OutputsUnknown(inner) =>
                Self::OutputsUnknown { inner: Arc::new(inner.into()) },
            ReceiveSession::WantsOutputs(inner) =>
                Self::WantsOutputs { inner: Arc::new(inner.into()) },
            ReceiveSession::WantsInputs(inner) =>
                Self::WantsInputs { inner: Arc::new(inner.into()) },
            ReceiveSession::WantsFeeRange(inner) =>
                Self::WantsFeeRange { inner: Arc::new(inner.into()) },
            ReceiveSession::ProvisionalProposal(inner) =>
                Self::ProvisionalProposal { inner: Arc::new(inner.into()) },
            ReceiveSession::PayjoinProposal(inner) =>
                Self::PayjoinProposal { inner: Arc::new(inner.into()) },
            ReceiveSession::HasReplyableError(inner) =>
                Self::HasReplyableError { inner: Arc::new(inner.into()) },
            ReceiveSession::Monitor(inner) => Self::Monitor { inner: Arc::new(inner.into()) },
            ReceiveSession::Closed(session_outcome) =>
                Self::Closed { inner: Arc::new(session_outcome.into()) },
        }
    }
}

#[derive(uniffi::Object)]
pub struct ReplayResult {
    state: ReceiveSession,
    session_history: ReceiverSessionHistory,
}

#[uniffi::export]
impl ReplayResult {
    pub fn state(&self) -> ReceiveSession { self.state.clone() }

    pub fn session_history(&self) -> ReceiverSessionHistory { self.session_history.clone() }
}

#[uniffi::export]
pub fn replay_receiver_event_log(
    persister: Arc<dyn JsonReceiverSessionPersister>,
) -> Result<ReplayResult, ReceiverReplayError> {
    let adapter = CallbackPersisterAdapter::new(persister);
    let (state, session_history) = payjoin::receive::v2::replay_event_log(&adapter)?;
    Ok(ReplayResult { state: state.into(), session_history: session_history.into() })
}

/// Represents the status of a session that can be inferred from the information in the session
/// event log.
#[derive(uniffi::Object)]
pub struct ReceiverSessionStatus(payjoin::receive::v2::SessionStatus);

impl From<payjoin::receive::v2::SessionStatus> for ReceiverSessionStatus {
    fn from(value: payjoin::receive::v2::SessionStatus) -> Self { Self(value) }
}

impl From<ReceiverSessionStatus> for payjoin::receive::v2::SessionStatus {
    fn from(value: ReceiverSessionStatus) -> Self { value.0 }
}

#[derive(Clone, uniffi::Object)]
pub struct ReceiverSessionHistory(pub payjoin::receive::v2::SessionHistory);

impl From<payjoin::receive::v2::SessionHistory> for ReceiverSessionHistory {
    fn from(value: payjoin::receive::v2::SessionHistory) -> Self { Self(value) }
}

#[uniffi::export]
impl ReceiverSessionHistory {
    /// Receiver session Payjoin URI
    pub fn pj_uri(&self) -> Arc<crate::PjUri> { Arc::new(self.0.pj_uri().into()) }

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<Vec<u8>> {
        self.0.fallback_tx().map(|tx| payjoin::bitcoin::consensus::encode::serialize(&tx))
    }

    /// Helper method to query the current status of the session.
    pub fn status(&self) -> ReceiverSessionStatus { self.0.status().into() }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct InitialReceiveTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::NextStateTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl InitialReceiveTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonReceiverSessionPersister>,
    ) -> Result<Initialized, ForeignError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        let res = value.save(&adapter)?;
        Ok(res.into())
    }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct ReceiverBuilder(payjoin::receive::v2::ReceiverBuilder);

/// Primitive representation of a transaction output for the FFI boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PlainTxOut {
    /// Amount in satoshis.
    pub value_sat: u64,
    /// Raw scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

impl From<PlainTxOut> for payjoin::bitcoin::TxOut {
    fn from(value: PlainTxOut) -> Self {
        payjoin::bitcoin::TxOut {
            value: Amount::from_sat(value.value_sat),
            script_pubkey: payjoin::bitcoin::ScriptBuf::from_bytes(value.script_pubkey),
        }
    }
}

impl From<payjoin::bitcoin::TxOut> for PlainTxOut {
    fn from(value: payjoin::bitcoin::TxOut) -> Self {
        PlainTxOut {
            value_sat: value.value.to_sat(),
            script_pubkey: value.script_pubkey.into_bytes(),
        }
    }
}

/// Primitive representation of a transaction input for the FFI boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PlainTxIn {
    pub previous_output: PlainOutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

impl PlainTxIn {
    fn into_core(self) -> Result<payjoin::bitcoin::TxIn, InputPairError> {
        let previous_output = self.previous_output.into_core()?;
        Ok(payjoin::bitcoin::TxIn {
            previous_output,
            script_sig: payjoin::bitcoin::ScriptBuf::from_bytes(self.script_sig),
            sequence: payjoin::bitcoin::Sequence(self.sequence),
            witness: self.witness.into(),
        })
    }
}

/// Primitive representation of an outpoint for the FFI boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PlainOutPoint {
    /// Hex-encoded txid (big-endian).
    pub txid: String,
    /// Output index.
    pub vout: u32,
}

impl From<payjoin::bitcoin::OutPoint> for PlainOutPoint {
    fn from(value: payjoin::bitcoin::OutPoint) -> Self {
        PlainOutPoint { txid: value.txid.to_string(), vout: value.vout }
    }
}

impl PlainOutPoint {
    fn into_core(self) -> Result<payjoin::bitcoin::OutPoint, InputPairError> {
        let txid = payjoin::bitcoin::Txid::from_str(&self.txid)
            .map_err(|_| InputPairError::invalid_outpoint(self.txid, self.vout))?;
        Ok(payjoin::bitcoin::OutPoint { txid, vout: self.vout })
    }
}

/// Primitive representation of a PSBT input for the FFI boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PlainPsbtInput {
    pub witness_utxo: Option<PlainTxOut>,
    pub redeem_script: Option<Vec<u8>>,
    pub witness_script: Option<Vec<u8>>,
}

impl PlainPsbtInput {
    fn into_core(self) -> payjoin::bitcoin::psbt::Input {
        payjoin::bitcoin::psbt::Input {
            witness_utxo: self.witness_utxo.map(Into::into),
            redeem_script: self.redeem_script.map(payjoin::bitcoin::ScriptBuf::from_bytes),
            witness_script: self.witness_script.map(payjoin::bitcoin::ScriptBuf::from_bytes),
            ..Default::default()
        }
    }
}

/// Primitive representation of a weight measurement.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PlainWeight {
    pub weight_units: u64,
}

impl From<PlainWeight> for payjoin::bitcoin::Weight {
    fn from(value: PlainWeight) -> Self { payjoin::bitcoin::Weight::from_wu(value.weight_units) }
}

impl From<payjoin::bitcoin::Weight> for PlainWeight {
    fn from(value: payjoin::bitcoin::Weight) -> Self { PlainWeight { weight_units: value.to_wu() } }
}

#[uniffi::export]
impl ReceiverBuilder {
    /// Creates a new [`Initialized`] with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
    #[uniffi::constructor]
    pub fn new(
        address: String,
        directory: String,
        ohttp_keys: Arc<OhttpKeys>,
    ) -> Result<Self, ReceiverBuilderError> {
        let parsed_address = payjoin::bitcoin::Address::from_str(address.as_str())
            .map_err(ReceiverBuilderError::from)?
            .assume_checked();
        Ok(Self(
            payjoin::receive::v2::ReceiverBuilder::new(
                parsed_address,
                directory,
                Arc::unwrap_or_clone(ohttp_keys).into(),
            )
            .map_err(ReceiverBuilderError::from)?,
        ))
    }

    pub fn with_amount(&self, amount_sats: u64) -> Self {
        Self(self.0.clone().with_amount(Amount::from_sat(amount_sats)))
    }

    pub fn with_expiration(&self, expiration: u64) -> Self {
        Self(self.0.clone().with_expiration(Duration::from_secs(expiration)))
    }

    /// Set the maximum effective fee rate the receiver is willing to pay for their own input/output contributions
    pub fn with_max_fee_rate(
        &self,
        max_effective_fee_rate_sat_per_vb: u64,
    ) -> Result<Self, PayjoinFeeRateError> {
        let fee_rate = FeeRate::from_sat_per_vb(max_effective_fee_rate_sat_per_vb)
            .ok_or_else(|| PayjoinFeeRateError::overflow(max_effective_fee_rate_sat_per_vb))?;
        Ok(Self(self.0.clone().with_max_fee_rate(fee_rate)))
    }

    pub fn build(&self) -> InitialReceiveTransition {
        InitialReceiveTransition(Arc::new(RwLock::new(Some(self.0.clone().build()))))
    }
}

impl From<payjoin::receive::v2::ReceiverBuilder> for ReceiverBuilder {
    fn from(value: payjoin::receive::v2::ReceiverBuilder) -> Self { Self(value) }
}

impl From<ReceiverBuilder> for payjoin::receive::v2::ReceiverBuilder {
    fn from(value: ReceiverBuilder) -> Self { value.0 }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Object)]
pub struct Initialized(payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>);

impl From<Initialized> for payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized> {
    fn from(value: Initialized) -> Self { value.0 }
}

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>> for Initialized {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct InitializedTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeFatalTransitionWithNoResults<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>,
                    payjoin::receive::ProtocolError,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl InitializedTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonReceiverSessionPersister>,
    ) -> Result<InitializedTransitionOutcome, ReceiverPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        let res = value.save(&adapter).map_err(ReceiverPersistedError::from)?;
        Ok(res.into())
    }
}

#[derive(uniffi::Enum)]
pub enum InitializedTransitionOutcome {
    Progress { inner: Arc<UncheckedOriginalPayload> },
    Stasis { inner: Arc<Initialized> },
}

impl
    From<
        payjoin::persist::OptionalTransitionOutcome<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>,
        >,
    > for InitializedTransitionOutcome
{
    fn from(
        value: payjoin::persist::OptionalTransitionOutcome<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>,
        >,
    ) -> Self {
        match value {
            payjoin::persist::OptionalTransitionOutcome::Progress(payload) =>
                Self::Progress { inner: Arc::new(payload.into()) },
            payjoin::persist::OptionalTransitionOutcome::Stasis(state) =>
                Self::Stasis { inner: Arc::new(state.into()) },
        }
    }
}

#[derive(uniffi::Record)]
pub struct RequestResponse {
    pub request: Request,
    pub client_response: Arc<ClientResponse>,
}

#[uniffi::export]
impl Initialized {
    /// Construct an OHTTP encapsulated GET request, polling the mailbox for the Original PSBT
    pub fn create_poll_request(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestResponse, ReceiverError> {
        self.0
            .create_poll_request(ohttp_relay)
            .map(|(req, ctx)| RequestResponse {
                request: req.into(),
                client_response: Arc::new(ctx.into()),
            })
            .map_err(Into::into)
    }

    /// The response can either be an UncheckedOriginalPayload or an ACCEPTED message indicating no UncheckedOriginalPayload is available yet.
    pub fn process_response(&self, body: &[u8], ctx: &ClientResponse) -> InitializedTransition {
        InitializedTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_response(body, ctx.into()),
        ))))
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri(&self) -> crate::PjUri {
        <Self as Into<payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>>>::into(
            self.clone(),
        )
        .pj_uri()
        .into()
    }
}

#[derive(Clone, uniffi::Object)]
pub struct UncheckedOriginalPayload(
    payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>,
);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>>
    for UncheckedOriginalPayload
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>,
    ) -> Self {
        Self(value)
    }
}

impl From<UncheckedOriginalPayload>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>
{
    fn from(value: UncheckedOriginalPayload) -> Self { value.0 }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct UncheckedOriginalPayloadTransition(
    Arc<
        RwLock<
            Option<
                MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned>,
                    payjoin::receive::Error,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(UncheckedOriginalPayloadTransition, MaybeInputsOwned);

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct AssumeInteractiveTransition(
    Arc<
        RwLock<
            Option<
                NextStateTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(AssumeInteractiveTransition, MaybeInputsOwned);

#[uniffi::export(with_foreign)]
pub trait CanBroadcast: Send + Sync {
    fn callback(&self, tx: Vec<u8>) -> Result<bool, ForeignError>;
}

#[uniffi::export]
impl UncheckedOriginalPayload {
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: Arc<dyn CanBroadcast>,
    ) -> UncheckedOriginalPayloadTransition {
        UncheckedOriginalPayloadTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_broadcast_suitability(
                min_fee_rate.map(FeeRate::from_sat_per_kwu),
                |transaction| {
                    can_broadcast
                        .callback(payjoin::bitcoin::consensus::encode::serialize(transaction))
                        .map_err(|e| ImplementationError::new(e).into())
                },
            ),
        ))))
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> AssumeInteractiveTransition {
        AssumeInteractiveTransition(Arc::new(RwLock::new(Some(
            self.0.clone().assume_interactive_receiver(),
        ))))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsOwned(payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned>>
    for MaybeInputsOwned
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsOwned>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct MaybeInputsOwnedTransition(
    Arc<
        RwLock<
            Option<
                MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen>,
                    payjoin::receive::Error,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(MaybeInputsOwnedTransition, MaybeInputsSeen);

#[uniffi::export(with_foreign)]
pub trait IsScriptOwned: Send + Sync {
    fn callback(&self, script: Vec<u8>) -> Result<bool, ForeignError>;
}

#[uniffi::export]
impl MaybeInputsOwned {
    ///The Sender’s Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::encode::serialize(
            &self.0.clone().extract_tx_to_schedule_broadcast(),
        )
    }
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Arc<dyn IsScriptOwned>,
    ) -> MaybeInputsOwnedTransition {
        MaybeInputsOwnedTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_inputs_not_owned(&mut |input| {
                is_owned.callback(input.to_bytes()).map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsSeen(payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen>>
    for MaybeInputsSeen
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::MaybeInputsSeen>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct MaybeInputsSeenTransition(
    Arc<
        RwLock<
            Option<
                MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown>,
                    payjoin::receive::Error,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(MaybeInputsSeenTransition, OutputsUnknown);

#[uniffi::export(with_foreign)]
pub trait IsOutputKnown: Send + Sync {
    fn callback(&self, outpoint: PlainOutPoint) -> Result<bool, ForeignError>;
}

#[uniffi::export]
impl MaybeInputsSeen {
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Arc<dyn IsOutputKnown>,
    ) -> MaybeInputsSeenTransition {
        MaybeInputsSeenTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_no_inputs_seen_before(&mut |outpoint| {
                is_known
                    .callback(PlainOutPoint::from(*outpoint))
                    .map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Clone, uniffi::Object)]
pub struct OutputsUnknown(payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown>> for OutputsUnknown {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::OutputsUnknown>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct OutputsUnknownTransition(
    Arc<
        RwLock<
            Option<
                MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs>,
                    payjoin::receive::Error,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(OutputsUnknownTransition, WantsOutputs);

#[uniffi::export]
impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: Arc<dyn IsScriptOwned>,
    ) -> OutputsUnknownTransition {
        OutputsUnknownTransition(Arc::new(RwLock::new(Some(
            self.0.clone().identify_receiver_outputs(&mut |input| {
                is_receiver_output
                    .callback(input.to_bytes())
                    .map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

#[derive(uniffi::Object)]
pub struct WantsOutputs(payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs>> for WantsOutputs {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsOutputs>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct WantsOutputsTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::NextStateTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(WantsOutputsTransition, WantsInputs);

#[uniffi::export]
impl WantsOutputs {
    pub fn output_substitution(&self) -> OutputSubstitution { self.0.output_substitution() }

    pub fn replace_receiver_outputs(
        &self,
        replacement_outputs: Vec<PlainTxOut>,
        drain_script_pubkey: Vec<u8>,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let replacement_outputs: Vec<payjoin::bitcoin::TxOut> =
            replacement_outputs.into_iter().map(Into::into).collect();
        let drain_script = payjoin::bitcoin::ScriptBuf::from_bytes(drain_script_pubkey);
        self.0
            .clone()
            .replace_receiver_outputs(replacement_outputs, &drain_script)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn substitute_receiver_script(
        &self,
        output_script_pubkey: Vec<u8>,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let output_script = payjoin::bitcoin::ScriptBuf::from_bytes(output_script_pubkey);
        self.0
            .clone()
            .substitute_receiver_script(&output_script)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_outputs(&self) -> WantsOutputsTransition {
        WantsOutputsTransition(Arc::new(RwLock::new(Some(self.0.clone().commit_outputs()))))
    }
}

#[derive(uniffi::Object)]
pub struct WantsInputs(payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs>> for WantsInputs {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct WantsInputsTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::NextStateTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsFeeRange>,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(WantsInputsTransition, WantsFeeRange);

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
        let candidate_inputs: Vec<payjoin::receive::InputPair> =
            candidate_inputs.into_iter().map(|pair| Arc::unwrap_or_clone(pair).into()).collect();
        match self.0.clone().try_preserving_privacy(candidate_inputs) {
            Ok(t) => Ok(Arc::new(t.into())),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contribute_inputs(
        &self,
        replacement_inputs: Vec<Arc<InputPair>>,
    ) -> Result<Arc<WantsInputs>, InputContributionError> {
        let replacement_inputs: Vec<payjoin::receive::InputPair> =
            replacement_inputs.into_iter().map(|pair| Arc::unwrap_or_clone(pair).into()).collect();
        self.0
            .clone()
            .contribute_inputs(replacement_inputs)
            .map(|t| Arc::new(t.into()))
            .map_err(Into::into)
    }

    pub fn commit_inputs(&self) -> WantsInputsTransition {
        WantsInputsTransition(Arc::new(RwLock::new(Some(self.0.clone().commit_inputs()))))
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct InputPair(payjoin::receive::InputPair);

#[uniffi::export]
impl InputPair {
    #[uniffi::constructor]
    pub fn new(
        txin: PlainTxIn,
        psbtin: PlainPsbtInput,
        expected_weight: Option<PlainWeight>,
    ) -> Result<Self, InputPairError> {
        let txin = txin.into_core()?;
        let psbtin = psbtin.into_core();
        let expected_weight = expected_weight.map(Into::into);
        payjoin::receive::InputPair::new(txin, psbtin, expected_weight)
            .map(Self)
            .map_err(|err| InputPairError::InvalidPsbtInput(Arc::new(err.into())))
    }
}

impl From<InputPair> for payjoin::receive::InputPair {
    fn from(value: InputPair) -> Self { value.0 }
}

impl From<payjoin::receive::InputPair> for InputPair {
    fn from(value: payjoin::receive::InputPair) -> Self { Self(value) }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct WantsFeeRangeTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal>,
                    payjoin::receive::ProtocolError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(WantsFeeRangeTransition, ProvisionalProposal);

#[derive(uniffi::Object)]
pub struct WantsFeeRange(payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsFeeRange>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsFeeRange>> for WantsFeeRange {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsFeeRange>) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl WantsFeeRange {
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
    /// If not provided, `min_fee_rate_sat_per_vb` and `max_effective_fee_rate_sat_per_vb` default to the
    /// minimum possible relay fee.
    ///
    /// The minimum effective fee limit is the highest of the minimum limit set by the sender in
    /// the original proposal parameters and the limit passed in the `min_fee_rate_sat_per_vb` parameter.
    pub fn apply_fee_range(
        &self,
        min_fee_rate_sat_per_vb: Option<u64>,
        max_effective_fee_rate_sat_per_vb: Option<u64>,
    ) -> WantsFeeRangeTransition {
        WantsFeeRangeTransition(Arc::new(RwLock::new(Some(self.0.clone().apply_fee_range(
            min_fee_rate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
            max_effective_fee_rate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
        )))))
    }
}

#[derive(uniffi::Object)]
pub struct ProvisionalProposal(
    pub payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal>,
);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal>>
    for ProvisionalProposal
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::ProvisionalProposal>,
    ) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct ProvisionalProposalTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeTransientTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>,
                    payjoin::ImplementationError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(ProvisionalProposalTransition, PayjoinProposal);

#[uniffi::export(with_foreign)]
pub trait ProcessPsbt: Send + Sync {
    fn callback(&self, psbt: String) -> Result<String, ForeignError>;
}

#[uniffi::export]
impl ProvisionalProposal {
    pub fn finalize_proposal(
        &self,
        process_psbt: Arc<dyn ProcessPsbt>,
    ) -> ProvisionalProposalTransition {
        ProvisionalProposalTransition(Arc::new(RwLock::new(Some(
            self.0.clone().finalize_proposal(|pre_processed| {
                let psbt = process_psbt
                    .callback(pre_processed.to_string())
                    .map_err(ImplementationError::new)?;
                Ok(Psbt::from_str(&psbt).map_err(ImplementationError::new)?)
            }),
        ))))
    }

    pub fn psbt_to_sign(&self) -> String { self.0.clone().psbt_to_sign().to_string() }
}

#[derive(Clone, uniffi::Object)]
pub struct PayjoinProposal(
    pub payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>,
);

impl From<PayjoinProposal>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>
{
    fn from(value: PayjoinProposal) -> Self { value.0 }
}

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>>
    for PayjoinProposal
{
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct PayjoinProposalTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeFatalTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::Monitor>,
                    payjoin::receive::ProtocolError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(PayjoinProposalTransition, Monitor);

#[uniffi::export]
impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> Vec<PlainOutPoint> {
        let mut outpoints: Vec<PlainOutPoint> = Vec::new();
        for o in <PayjoinProposal as Into<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>,
        >>::into(self.clone())
        .utxos_to_be_locked()
        {
            outpoints.push(PlainOutPoint::from(*o));
        }
        outpoints
    }

    pub fn psbt(&self) -> String {
        <PayjoinProposal as Into<
            payjoin::receive::v2::Receiver<payjoin::receive::v2::PayjoinProposal>,
        >>::into(self.clone())
        .psbt()
        .clone()
        .to_string()
    }

    /// Construct an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn create_post_request(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestResponse, ReceiverError> {
        self.0.clone().create_post_request(ohttp_relay).map_err(Into::into).map(|(req, ctx)| {
            RequestResponse { request: req.into(), client_response: Arc::new(ctx.into()) }
        })
    }

    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful, it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or choose to broadcast the original PSBT.
    pub fn process_response(
        &self,
        body: &[u8],
        ohttp_context: &ClientResponse,
    ) -> PayjoinProposalTransition {
        PayjoinProposalTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_response(body, ohttp_context.into()),
        ))))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct HasReplyableError(
    pub payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
);

impl From<HasReplyableError>
    for payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>
{
    fn from(value: HasReplyableError) -> Self { value.0 }
}

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>>
    for HasReplyableError
{
    fn from(
        value: payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
    ) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
pub struct HasReplyableErrorTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeSuccessTransition<
                    payjoin::receive::v2::SessionEvent,
                    (),
                    payjoin::receive::ProtocolError,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl HasReplyableErrorTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonReceiverSessionPersister>,
    ) -> Result<(), ReceiverPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        value.save(&adapter).map_err(ReceiverPersistedError::from)?;
        Ok(())
    }
}

#[uniffi::export]
impl HasReplyableError {
    pub fn create_error_request(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestResponse, SessionError> {
        self.0.clone().create_error_request(ohttp_relay).map_err(Into::into).map(|(req, ctx)| {
            RequestResponse { request: req.into(), client_response: Arc::new(ctx.into()) }
        })
    }

    pub fn process_error_response(
        &self,
        body: &[u8],
        ohttp_context: &ClientResponse,
    ) -> HasReplyableErrorTransition {
        HasReplyableErrorTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_error_response(body, ohttp_context.into()),
        ))))
    }
}

#[uniffi::export(with_foreign)]
pub trait TransactionExists: Send + Sync {
    // TODO: Is there an ffi exported txid type that we can use here?
    // TODO: Is there a ffi type for the serialized tx?
    fn callback(&self, txid: String) -> Result<Option<Vec<u8>>, ForeignError>;
}

#[allow(clippy::type_complexity)]
#[derive(uniffi::Object)]
pub struct MonitorTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeFatalOrSuccessTransition<
                    payjoin::receive::v2::SessionEvent,
                    payjoin::receive::v2::Receiver<payjoin::receive::v2::Monitor>,
                    payjoin::receive::Error,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl MonitorTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonReceiverSessionPersister>,
    ) -> Result<(), ReceiverPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        value.save(&adapter).map_err(ReceiverPersistedError::from)?;
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct Monitor(pub payjoin::receive::v2::Receiver<payjoin::receive::v2::Monitor>);

impl From<payjoin::receive::v2::Receiver<payjoin::receive::v2::Monitor>> for Monitor {
    fn from(value: payjoin::receive::v2::Receiver<payjoin::receive::v2::Monitor>) -> Self {
        Self(value)
    }
}

fn try_deserialize_tx(
    buf: Vec<u8>,
) -> Result<payjoin::bitcoin::transaction::Transaction, ForeignError> {
    payjoin::bitcoin::transaction::Transaction::consensus_decode(&mut buf.as_slice())
        .map_err(|e| ForeignError::InternalError(e.to_string()))
}

#[uniffi::export]
impl Monitor {
    pub fn monitor(&self, transaction_exists: Arc<dyn TransactionExists>) -> MonitorTransition {
        MonitorTransition(Arc::new(RwLock::new(Some(self.0.clone().check_payment(|txid| {
            transaction_exists
                .callback(txid.to_string())
                .and_then(|buf| buf.map(try_deserialize_tx).transpose())
                .map_err(|e| ImplementationError::new(e).into())
        })))))
    }
}

/// Session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
pub trait JsonReceiverSessionPersister: Send + Sync {
    fn save(&self, event: String) -> Result<(), ForeignError>;
    fn load(&self) -> Result<Vec<String>, ForeignError>;
    fn close(&self) -> Result<(), ForeignError>;
}

/// Adapter for the [JsonReceiverSessionPersister] trait to use the save and load callbacks.
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

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let uni_event: ReceiverSessionEvent = event.into();
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
                    ReceiverSessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(|e| e.into())
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
