use std::sync::Arc;

use super::InputPair;
use crate::bitcoin_ffi::{Network, OutPoint, Script, TxOut};
use crate::error::PayjoinError;
use crate::{ClientResponse, OhttpKeys, Request};

#[derive(Clone, Debug, uniffi::Object)]
pub struct Receiver(pub super::Receiver);

impl From<Receiver> for super::Receiver {
    fn from(value: Receiver) -> Self {
        value.0
    }
}

impl From<super::Receiver> for Receiver {
    fn from(value: super::Receiver) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl Receiver {
    /// Creates a new `SessionInitializer` with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `network`: The network to use for address verification.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `ohttp_relay`: The URL of the OHTTP relay, used to keep client IP address confidential.
    /// - `expire_after`: The duration in seconds after which the session expires.
    ///
    /// # Returns
    /// A new instance of `SessionInitializer`.
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/pull/1483)
    #[uniffi::constructor]
    pub fn new(
        address: String,
        network: Network,
        directory: String,
        ohttp_keys: Arc<OhttpKeys>,
        expire_after: Option<u64>,
    ) -> Result<Self, PayjoinError> {
        super::Receiver::new(address, network, directory, (*ohttp_keys).clone(), expire_after)
            .map(Into::into)
    }

    pub fn extract_req(&self, ohttp_relay: String) -> Result<RequestResponse, PayjoinError> {
        self.0
            .extract_req(ohttp_relay)
            .map(|(request, ctx)| RequestResponse { request, client_response: Arc::new(ctx) })
    }

    ///The response can either be an UncheckedProposal or an ACCEPTED message indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &self,
        body: &[u8],
        context: Arc<ClientResponse>,
    ) -> Result<Option<Arc<UncheckedProposal>>, PayjoinError> {
        <Self as Into<super::Receiver>>::into(self.clone())
            .process_res(body, context.as_ref())
            .map(|e| e.map(|x| Arc::new(x.into())))
    }

    ///The per-session public key to use as an identifier
    pub fn id(&self) -> String {
        self.0.id()
    }

    pub fn to_json(&self) -> Result<String, PayjoinError> {
        self.0.to_json()
    }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, PayjoinError> {
        super::Receiver::from_json(json).map(Into::into)
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RequestResponse {
    pub request: Request,
    pub client_response: Arc<ClientResponse>,
}

#[uniffi::export(callback_interface)]
pub trait CanBroadcast {
    fn callback(&self, tx: Vec<u8>) -> Result<bool, PayjoinError>;
}

/// The sender’s original PSBT and optional parameters
///
/// This type is used to proces the request. It is returned by UncheckedProposal::from_request().
///
/// If you are implementing an interactive payment processor, you should get extract the original transaction with get_transaction_to_schedule_broadcast() and schedule, followed by checking that the transaction can be broadcast with check_can_broadcast. Otherwise it is safe to call assume_interactive_receive to proceed with validation.
#[derive(Clone, uniffi::Object)]
pub struct UncheckedProposal(super::UncheckedProposal);

impl From<super::UncheckedProposal> for UncheckedProposal {
    fn from(value: super::UncheckedProposal) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl UncheckedProposal {
    /// The Sender’s Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> Vec<u8> {
        self.0.extract_tx_to_schedule_broadcast()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender can be broadcast, i.e. testmempoolaccept bitcoind rpc returns { “allowed”: true,.. } for get_transaction_to_check_broadcast() before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor. Such so called “non-interactive” receivers are otherwise vulnerable to probing attacks. If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost. Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: Box<dyn CanBroadcast>,
    ) -> Result<Arc<MaybeInputsOwned>, PayjoinError> {
        self.0
            .clone()
            .check_broadcast_suitability(min_fee_rate, |transaction| {
                can_broadcast.callback(transaction.to_vec())
            })
            .map(|e| Arc::new(e.into()))
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> Arc<MaybeInputsOwned> {
        Arc::new(self.0.assume_interactive_receiver().into())
    }
}

/// Type state to validate that the Original PSBT has no receiver-owned inputs.
/// Call check_no_receiver_owned_inputs() to proceed.
#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsOwned(super::MaybeInputsOwned);

impl From<super::MaybeInputsOwned> for MaybeInputsOwned {
    fn from(value: super::MaybeInputsOwned) -> Self {
        Self(value)
    }
}

#[uniffi::export(callback_interface)]
pub trait IsScriptOwned {
    fn callback(&self, script: Vec<u8>) -> Result<bool, PayjoinError>;
}

#[uniffi::export]
impl MaybeInputsOwned {
    ///Check that the Original PSBT has no receiver-owned inputs. Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<MaybeInputsSeen>, PayjoinError> {
        self.0
            .check_inputs_not_owned(|input| is_owned.callback(input.to_vec()))
            .map(|t| Arc::new(t.into()))
    }
}

#[uniffi::export(callback_interface)]
pub trait IsOutputKnown {
    fn callback(&self, outpoint: OutPoint) -> Result<bool, PayjoinError>;
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call check_no_inputs_seen to proceed.
#[derive(Clone, uniffi::Object)]
pub struct MaybeInputsSeen(super::MaybeInputsSeen);

impl From<super::MaybeInputsSeen> for MaybeInputsSeen {
    fn from(value: super::MaybeInputsSeen) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before. This prevents probing attacks. This prevents reentrant Payjoin, where a sender proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Box<dyn IsOutputKnown>,
    ) -> Result<Arc<OutputsUnknown>, PayjoinError> {
        self.0
            .clone()
            .check_no_inputs_seen_before(|outpoint| is_known.callback(outpoint.clone()))
            .map(|t| Arc::new(t.into()))
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money. Identify those outputs with identify_receiver_outputs() to proceed
#[derive(Clone, uniffi::Object)]
pub struct OutputsUnknown(super::OutputsUnknown);

impl From<super::OutputsUnknown> for OutputsUnknown {
    fn from(value: super::OutputsUnknown) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<WantsOutputs>, PayjoinError> {
        self.0
            .clone()
            .identify_receiver_outputs(|output_script| {
                is_receiver_output.callback(output_script.to_vec())
            })
            .map(|t| Arc::new(t.into()))
    }
}

#[derive(uniffi::Object)]
pub struct WantsOutputs(super::WantsOutputs);

impl From<super::WantsOutputs> for WantsOutputs {
    fn from(value: super::WantsOutputs) -> Self {
        Self(value)
    }
}
#[uniffi::export]
impl WantsOutputs {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.0.is_output_substitution_disabled()
    }

    pub fn replace_receiver_outputs(
        &self,
        replacement_outputs: Vec<TxOut>,
        drain_script: Arc<Script>,
    ) -> Result<Arc<WantsOutputs>, PayjoinError> {
        self.0
            .replace_receiver_outputs(replacement_outputs, &drain_script)
            .map(|t| Arc::new(t.into()))
    }

    pub fn commit_outputs(&self) -> Arc<WantsInputs> {
        Arc::new(self.0.commit_outputs().into())
    }

    pub fn substitute_receiver_script(
        &self,
        output_script: Arc<Script>,
    ) -> Result<Arc<WantsOutputs>, PayjoinError> {
        self.0
            .substitute_receiver_script(&output_script)
            .map(|t| Arc::new(t.into()))
            .map_err(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct WantsInputs(super::WantsInputs);

impl From<super::WantsInputs> for WantsInputs {
    fn from(value: super::WantsInputs) -> Self {
        Self(value)
    }
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
    ) -> Result<Arc<InputPair>, PayjoinError> {
        let candidate_inputs: Vec<InputPair> = candidate_inputs
            .into_iter()
            .map(|pair| Arc::try_unwrap(pair).unwrap_or_else(|arc| (*arc).clone()))
            .collect();

        self.0.try_preserving_privacy(candidate_inputs).map(Arc::new)
    }

    pub fn contribute_inputs(
        &self,
        replacement_inputs: Vec<Arc<InputPair>>,
    ) -> Result<Arc<WantsInputs>, PayjoinError> {
        let replacement_inputs: Vec<InputPair> = replacement_inputs
            .into_iter()
            .map(|pair| Arc::try_unwrap(pair).unwrap_or_else(|arc| (*arc).clone()))
            .collect();
        self.0.contribute_inputs(replacement_inputs).map(|t| Arc::new(t.into()))
    }

    pub fn commit_inputs(&self) -> Arc<ProvisionalProposal> {
        Arc::new(self.0.commit_inputs().into())
    }
}

#[derive(uniffi::Object)]
pub struct ProvisionalProposal(super::ProvisionalProposal);

impl From<super::ProvisionalProposal> for ProvisionalProposal {
    fn from(value: super::ProvisionalProposal) -> Self {
        Self(value)
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[uniffi::export]
impl ProvisionalProposal {
    pub fn finalize_proposal(
        &self,
        process_psbt: Box<dyn ProcessPsbt>,
        min_feerate_sat_per_vb: Option<u64>,
        max_effective_fee_rate_sat_per_vb: Option<u64>,
    ) -> Result<Arc<PayjoinProposal>, PayjoinError> {
        self.0
            .finalize_proposal(
                |psbt| process_psbt.callback(psbt.to_string()),
                min_feerate_sat_per_vb,
                max_effective_fee_rate_sat_per_vb,
            )
            .map(|e| Arc::new(e.into()))
    }
}

#[uniffi::export(callback_interface)]
pub trait ProcessPsbt {
    fn callback(&self, psbt: String) -> Result<String, PayjoinError>;
}

#[derive(Clone, uniffi::Object)]
pub struct PayjoinProposal(super::PayjoinProposal);

impl From<PayjoinProposal> for super::PayjoinProposal {
    fn from(value: PayjoinProposal) -> Self {
        value.0
    }
}

impl From<super::PayjoinProposal> for PayjoinProposal {
    fn from(value: super::PayjoinProposal) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> Vec<crate::OutPoint> {
        let mut outpoints: Vec<crate::OutPoint> = Vec::new();
        for e in <PayjoinProposal as Into<super::PayjoinProposal>>::into(self.clone())
            .utxos_to_be_locked()
        {
            outpoints.push(e.to_owned());
        }
        outpoints
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        <PayjoinProposal as Into<super::PayjoinProposal>>::into(self.clone())
            .is_output_substitution_disabled()
    }

    pub fn psbt(&self) -> String {
        self.0.psbt()
    }

    pub fn extract_v2_req(&self, ohttp_relay: String) -> Result<RequestResponse, PayjoinError> {
        let (req, res) = self.0.extract_v2_req(ohttp_relay)?;
        Ok(RequestResponse { request: req, client_response: Arc::new(res) })
    }

    ///Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful, it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or choose to broadcast the original PSBT.
    pub fn process_res(&self, body: &[u8], ctx: Arc<ClientResponse>) -> Result<(), PayjoinError> {
        self.0.process_res(body, ctx.as_ref())
    }
}
