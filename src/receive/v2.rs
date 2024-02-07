use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use payjoin::bitcoin::psbt::Psbt;
use payjoin::Error as PdkError;

use crate::error::PayjoinError;
use crate::receive::{
    CanBroadcast, IsOutputKnown, IsScriptOwned, ProcessPartiallySignedTransaction,
};
use crate::types::{OutPoint, Request, TxOut};

pub struct ClientResponse(Mutex<Option<ohttp::ClientResponse>>);

impl From<&ClientResponse> for ohttp::ClientResponse {
    fn from(value: &ClientResponse) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ClientResponse moved out of memory")
    }
}
impl From<ohttp::ClientResponse> for ClientResponse {
    fn from(value: ohttp::ClientResponse) -> Self {
        Self(Mutex::new(Some(value)))
    }
}

pub struct RequestResponse {
    pub request: Request,
    pub client_response: Arc<ClientResponse>,
}

#[derive(Clone, Debug)]
pub struct Enroller(pub payjoin::receive::v2::Enroller);
impl From<Enroller> for payjoin::receive::v2::Enroller {
    fn from(value: Enroller) -> Self {
        value.0
    }
}

impl From<payjoin::receive::v2::Enroller> for Enroller {
    fn from(value: payjoin::receive::v2::Enroller) -> Self {
        Self(value)
    }
}

impl Enroller {
    pub fn from_relay_config(
        relay_url: String,
        ohttp_config_base64: String,
        ohttp_proxy_url: String,
    ) -> Self {
        payjoin::receive::v2::Enroller::from_relay_config(
            relay_url.as_str(),
            ohttp_config_base64.as_str(),
            ohttp_proxy_url.as_str(),
        )
        .into()
    }
    pub fn subdirectory(&self) -> String {
        <Enroller as Into<payjoin::receive::v2::Enroller>>::into(self.clone()).subdirectory()
    }
    pub fn payjoin_subdir(&self) -> String {
        <Enroller as Into<payjoin::receive::v2::Enroller>>::into(self.clone()).payjoin_subdir()
    }
    pub fn extract_req(&self) -> Result<RequestResponse, PayjoinError> {
        match self.0.clone().extract_req() {
            Ok(e) => {
                Ok(RequestResponse { request: e.0.into(), client_response: Arc::new(e.1.into()) })
            }
            Err(e) => Err(PayjoinError::V2Error { message: e.to_string() }),
        }
    }
    pub fn process_res(
        &self,
        body: Vec<u8>,
        ctx: Arc<ClientResponse>,
    ) -> Result<Arc<Enrolled>, PayjoinError> {
        match <Enroller as Into<payjoin::receive::v2::Enroller>>::into(self.clone())
            .process_res(Cursor::new(body), ctx.as_ref().into())
        {
            Ok(e) => Ok(Arc::new(Enrolled(e))),
            Err(e) => Err(e.into()),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Enrolled(payjoin::receive::v2::Enrolled);

impl From<Enrolled> for payjoin::receive::v2::Enrolled {
    fn from(value: Enrolled) -> Self {
        value.0
    }
}

impl From<payjoin::receive::v2::Enrolled> for Enrolled {
    fn from(value: payjoin::receive::v2::Enrolled) -> Self {
        Self(value)
    }
}
impl Enrolled {
    pub fn pubkey(&self) -> Vec<u8> {
        <Enrolled as Into<payjoin::receive::v2::Enrolled>>::into(self.clone()).pubkey().to_vec()
    }
    pub fn fallback_target(&self) -> String {
        <Enrolled as Into<payjoin::receive::v2::Enrolled>>::into(self.clone()).fallback_target()
    }

    pub fn extract_req(&self) -> Result<RequestResponse, PayjoinError> {
        let (req, res) = self.0.clone().extract_req()?;
        Ok(RequestResponse { request: req.into(), client_response: Arc::new(res.into()) })
    }
    pub fn process_res(
        &self,
        body: Vec<u8>,
        context: Arc<ClientResponse>,
    ) -> Result<Option<Arc<V2UncheckedProposal>>, PayjoinError> {
        match <Enrolled as Into<payjoin::receive::v2::Enrolled>>::into(self.clone())
            .process_res(Cursor::new(body), context.as_ref().into())
        {
            Ok(e) => Ok(e.map(|x| Arc::new(x.into()))),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Clone)]
pub struct V2UncheckedProposal(payjoin::receive::v2::UncheckedProposal);

impl From<payjoin::receive::v2::UncheckedProposal> for V2UncheckedProposal {
    fn from(value: payjoin::receive::v2::UncheckedProposal) -> Self {
        Self(value)
    }
}
impl From<V2UncheckedProposal> for payjoin::receive::v2::UncheckedProposal {
    fn from(value: V2UncheckedProposal) -> Self {
        value.0
    }
}
impl V2UncheckedProposal {
    ///The Sender’s Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::encode::serialize(
            &self.0.clone().extract_tx_to_schedule_broadcast(),
        )
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `extract_tx_to_sheculed_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: Box<dyn CanBroadcast>,
    ) -> Result<Arc<V2MaybeInputsOwned>, PayjoinError> {
        let res = self.0.clone().check_broadcast_suitability(
            min_fee_rate.map(|x| payjoin::bitcoin::FeeRate::from_sat_per_kwu(x)),
            |tx| {
                match can_broadcast.callback(payjoin::bitcoin::consensus::encode::serialize(&tx)) {
                    Ok(e) => Ok(e),
                    Err(e) => Err(PdkError::Server(e.into())),
                }
            },
        );
        match res {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> Arc<V2MaybeInputsOwned> {
        Arc::new(self.0.clone().assume_interactive_receiver().into())
    }
}
#[derive(Clone)]
pub struct V2MaybeInputsOwned(payjoin::receive::v2::MaybeInputsOwned);
impl From<payjoin::receive::v2::MaybeInputsOwned> for V2MaybeInputsOwned {
    fn from(value: payjoin::receive::v2::MaybeInputsOwned) -> Self {
        Self(value)
    }
}
impl V2MaybeInputsOwned {
    ///Check that the Original PSBT has no receiver-owned inputs. Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    // An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<V2MaybeMixedInputScripts>, PayjoinError> {
        let owned_inputs = self.0.clone();
        match owned_inputs.check_inputs_not_owned(|input| {
            let res = is_owned.callback(input.to_bytes());
            match res {
                Ok(e) => Ok(e),
                Err(e) => Err(PdkError::Server(e.into())),
            }
        }) {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(PayjoinError::ServerError { message: e.to_string() }),
        }
    }
}
#[derive(Clone)]
pub struct V2MaybeMixedInputScripts(payjoin::receive::v2::MaybeMixedInputScripts);

impl From<payjoin::receive::v2::MaybeMixedInputScripts> for V2MaybeMixedInputScripts {
    fn from(value: payjoin::receive::v2::MaybeMixedInputScripts) -> Self {
        Self(value)
    }
}

impl V2MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(&self) -> Result<Arc<V2MaybeInputsSeen>, PayjoinError> {
        match self.0.clone().check_no_mixed_input_scripts() {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
}
#[derive(Clone)]
pub struct V2MaybeInputsSeen(payjoin::receive::v2::MaybeInputsSeen);
impl From<payjoin::receive::v2::MaybeInputsSeen> for V2MaybeInputsSeen {
    fn from(value: payjoin::receive::v2::MaybeInputsSeen) -> Self {
        Self(value)
    }
}

impl V2MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Box<dyn IsOutputKnown>,
    ) -> Result<Arc<V2OutputsUnknown>, PayjoinError> {
        match self.0.clone().check_no_inputs_seen_before(|outpoint| {
            let res = is_known.callback(outpoint.clone().into());
            match res {
                Ok(e) => Ok(e),
                Err(e) => Err(PdkError::Server(e.into())),
            }
        }) {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Clone)]
pub struct V2OutputsUnknown(payjoin::receive::v2::OutputsUnknown);

impl From<payjoin::receive::v2::OutputsUnknown> for V2OutputsUnknown {
    fn from(value: payjoin::receive::v2::OutputsUnknown) -> Self {
        Self(value)
    }
}

impl V2OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<V2ProvisionalProposal>, PayjoinError> {
        match self.0.clone().identify_receiver_outputs(|output_script| {
            let res = is_receiver_output.callback(output_script.to_bytes());
            match res {
                Ok(e) => Ok(e),
                Err(e) => Err(PdkError::Server(e.into())),
            }
        }) {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
}
pub struct V2ProvisionalProposal(Mutex<payjoin::receive::v2::ProvisionalProposal>);

impl From<payjoin::receive::v2::ProvisionalProposal> for V2ProvisionalProposal {
    fn from(value: payjoin::receive::v2::ProvisionalProposal) -> Self {
        Self(Mutex::new(value))
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
impl V2ProvisionalProposal {
    fn mutex_guard(&self) -> MutexGuard<'_, payjoin::receive::v2::ProvisionalProposal> {
        self.0.lock().unwrap()
    }
    ///Just replace an output address with
    pub fn substitute_output_address(
        &self,
        substitute_address: String,
    ) -> Result<(), PayjoinError> {
        let address =
            payjoin::bitcoin::Address::from_str(substitute_address.as_str())?.assume_checked();
        Ok(self.mutex_guard().substitute_output_address(address))
    }
    pub fn contribute_witness_input(
        &self,
        txo: TxOut,
        outpoint: OutPoint,
    ) -> Result<(), PayjoinError> {
        let txo: payjoin::bitcoin::blockdata::transaction::TxOut = txo.into();
        Ok(self.mutex_guard().contribute_witness_input(txo, outpoint.into()))
    }
    pub fn contribute_non_witness_input(
        &self,
        tx: Vec<u8>,
        outpoint: OutPoint,
    ) -> Result<(), PayjoinError> {
        let tx: payjoin::bitcoin::Transaction =
            payjoin::bitcoin::consensus::encode::deserialize(&*tx)?;
        Ok(self.mutex_guard().contribute_non_witness_input(tx, outpoint.into()))
    }
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
        candidate_inputs: HashMap<u64, OutPoint>,
    ) -> Result<OutPoint, PayjoinError> {
        let mut _candidate_inputs: HashMap<payjoin::bitcoin::Amount, payjoin::bitcoin::OutPoint> =
            HashMap::new();
        for (key, value) in candidate_inputs.iter() {
            _candidate_inputs.insert(
                payjoin::bitcoin::Amount::from_sat(key.to_owned()),
                value.to_owned().into(),
            );
        }

        match self.mutex_guard().try_preserving_privacy(_candidate_inputs) {
            Ok(e) => Ok(OutPoint { txid: e.txid.to_string(), vout: e.vout }),
            Err(e) => Err(e.into()),
        }
    }
    pub fn finalize_proposal(
        &self,
        process_psbt: Box<dyn ProcessPartiallySignedTransaction>,
        min_feerate_sat_per_vb: Option<u64>,
    ) -> Result<Arc<V2PayjoinProposal>, PayjoinError> {
        match self.mutex_guard().clone().finalize_proposal(
            |psbt| {
                match process_psbt.callback(psbt.to_string()) {
                    Ok(e) => Ok(Psbt::from_str(e.as_str()).expect("Invalid process_psbt ")),
                    Err(e) => Err(PdkError::Server(e.into())),
                }
            },
            min_feerate_sat_per_vb.and_then(|x| payjoin::bitcoin::FeeRate::from_sat_per_vb(x)),
        ) {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.

#[derive(Clone)]
pub struct V2PayjoinProposal(pub payjoin::receive::v2::PayjoinProposal);
impl From<V2PayjoinProposal> for payjoin::receive::v2::PayjoinProposal {
    fn from(value: V2PayjoinProposal) -> Self {
        value.0
    }
}
impl From<payjoin::receive::v2::PayjoinProposal> for V2PayjoinProposal {
    fn from(value: payjoin::receive::v2::PayjoinProposal) -> Self {
        Self(value)
    }
}

impl V2PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> Vec<OutPoint> {
        let mut outpoints: Vec<OutPoint> = Vec::new();
        for e in
            <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
                .utxos_to_be_locked()
        {
            outpoints.push((e.to_owned()).into())
        }
        outpoints
    }
    pub fn is_output_substitution_disabled(&self) -> bool {
        <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .is_output_substitution_disabled()
    }
    pub fn owned_vouts(&self) -> Vec<u64> {
        <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .owned_vouts()
            .iter()
            .map(|x| *x as u64)
            .collect()
    }
    pub fn psbt(&self) -> String {
        <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .psbt()
            .clone()
            .to_string()
    }

    pub fn extract_v1_req(&self) -> String {
        <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .extract_v1_req()
    }
    pub fn extract_v2_req(&self) -> Result<RequestResponse, PayjoinError> {
        let (req, res) = self.0.clone().extract_v2_req()?;
        Ok(RequestResponse { request: req.into(), client_response: Arc::new(res.into()) })
    }

    pub fn deserialize_res(
        &self,
        res: Vec<u8>,
        ohttp_context: Arc<ClientResponse>,
    ) -> Result<Vec<u8>, PayjoinError> {
        match <V2PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .deserialize_res(res, ohttp_context.as_ref().into())
        {
            Ok(e) => Ok(e),
            Err(e) => Err(e.into()),
        }
    }
}
