use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::{Arc};
use ohttp::KeyConfig;

use payjoin::{Error as PdkError};
use payjoin::bitcoin::psbt::Psbt;

use crate::error::PayjoinError;
use crate::receive::{CanBroadcast, IsOutputKnown, IsScriptOwned, ProcessPartiallySignedTransaction};
use crate::send::Request;
use crate::transaction::{PartiallySignedTransaction, Transaction};
use crate::{Address, FeeRate, OutPoint, ScriptBuf, TxOut};

pub struct ClientResponse(ohttp::ClientResponse);

impl From<ohttp::ClientResponse> for ClientResponse {
    fn from(value: ohttp::ClientResponse) -> Self {
        Self(value)
    }
}

pub struct ExtractReq {
    pub request: Request,
    pub client_response: Arc<ClientResponse>,
}

pub struct Enroller(payjoin::receive::v2::Enroller);
impl From<payjoin::receive::v2::Enroller> for Enroller {
    fn from(value: payjoin::receive::v2::Enroller) -> Self {
        Self(value)
    }
}
impl Enroller{
    pub fn from_relay_config(
        relay_url: String,
        ohttp_config_base64: String,
        ohttp_proxy_url: String
    ) -> Self{
       payjoin::receive::v2::Enroller::from_relay_config(relay_url.as_str(), ohttp_config_base64.as_str(), ohttp_proxy_url.as_str()).into()
    }
    pub fn subdirectory(&self) -> String{

        self.0.clone().subdirectory()
    }
}

#[derive(Clone)]
pub struct Enrolled(payjoin::receive::v2::Enrolled);

impl Enrolled {
    pub fn extract_req(&self) -> Result<ExtractReq, PayjoinError> {

        match self.0.extract_req() {
            Ok(e) => Ok(ExtractReq { request: e.0.into(), client_response: Arc::new(e.1.into()) }),
            Err(e) => Err(e.into()),
        }
    }
    ///The response can either be an UncheckedProposal or an ACCEPTED message indicating no UncheckedProposal is available yet.
    pub fn pubkey(&self) -> Vec<u8> {
        self.0.pubkey().as_slice().to_vec()
    }
    pub fn fallback_target(&self) -> String {
        self.0.fallback_target()
    }

//     pub fn process_res(
//         &self,
//         body: Vec<u8>,
//         context: ClientResponse
//     ) -> Result<Option<Arc<V2UncheckedProposal>>, PayjoinError>{
//         match self.0.process_res(Cursor::new(body), context.0){
//             Ok(e) => Ok(e.map(|x| Arc::new(x.into()))),
//             Err(e) => Err(e.into())
//         }
//     }
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
    pub fn extract_tx_to_schedule_broadcast(&self) -> Arc<Transaction> {
        Arc::new(self.0.clone().extract_tx_to_schedule_broadcast().into())
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
        min_fee_rate: Option<Arc<FeeRate>>,
        can_broadcast: Box<dyn CanBroadcast>,
    ) -> Result<Arc<V2MaybeInputsOwned>, PayjoinError> {
        let res =
            self.0.clone().check_broadcast_suitability(min_fee_rate.map(|x| (*x).into()), |tx| {
                match can_broadcast
                    .test_mempool_accept(payjoin::bitcoin::consensus::encode::serialize(&tx))
                {
                    Ok(e) => Ok(e),
                    Err(e) => Err(PdkError::Server(e.into())),
                }
            });
        match res {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver requires manual intervention, as in most consumer wallets.
    ///
    /// So-called “non-interactive” receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks. Those receivers call get_transaction_to_check_broadcast() and attest_tested_and_scheduled_broadcast() after making those checks downstream.
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
impl V2MaybeInputsOwned{
    /// Make sure that the original transaction inputs have never been seen before. This prevents probing attacks. This prevents reentrant Payjoin, where a sender proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<V2MaybeMixedInputScripts>, PayjoinError> {
        let owned_inputs = self.0.clone();
        match owned_inputs.check_inputs_not_owned(|input| {
            let res = is_owned.is_owned(Arc::new(ScriptBuf { internal: input.to_owned() }));
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
    /// Verify the original transaction did not have mixed input types Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints. This check is intended to prevent some types of wallet fingerprinting.
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

impl  V2MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before. This prevents probing attacks. This prevents reentrant Payjoin, where a sender proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Box<dyn IsOutputKnown>,
    ) -> Result<Arc<V2OutputsUnknown>, PayjoinError> {
        match self.0.clone().check_no_inputs_seen_before(|outpoint| {
            let res = is_known.is_known(outpoint.to_owned().into());
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
            let res = is_receiver_output
                .is_owned(Arc::new(ScriptBuf { internal: output_script.to_owned() }));
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
 pub struct V2ProvisionalProposal(payjoin::receive::v2::ProvisionalProposal);

impl From<payjoin::receive::v2::ProvisionalProposal> for V2ProvisionalProposal {
    fn from(value: payjoin::receive::v2::ProvisionalProposal) -> Self {
        Self(value)
    }
}

impl V2ProvisionalProposal {
    pub fn substitute_output_address(&self, substitute_address: Arc<Address>) {
        self.0.clone().substitute_output_address((*substitute_address).clone().into())
    }
    pub fn contribute_witness_input(&self, txo: TxOut, outpoint: OutPoint) {
        self.0.clone().contribute_witness_input(txo.into(), outpoint.into())
    }
    pub fn contribute_non_witness_input(&self, tx: Arc<Transaction>, outpoint: OutPoint) {
        self.0.clone().contribute_non_witness_input((*tx).clone().into(), outpoint.into())
    }
    /// Select receiver input such that the payjoin avoids surveillance. Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions. To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH “Unnecessary input heuristic” is one class of them to avoid. We define UIH1 and UIH2 according to the BlockSci practice BlockSci UIH1 and UIH2:
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

        match self.0.clone().try_preserving_privacy(_candidate_inputs) {
            Ok(e) => Ok(OutPoint { txid: e.txid.to_string(), vout: e.vout }),
            Err(e) => Err(e.into()),
        }
    }
    pub fn finalize_proposal(
        &self,
        process_psbt: Box<dyn ProcessPartiallySignedTransaction>,
        min_feerate_sat_per_vb: Option<Arc<FeeRate>>,
    ) -> Result<Arc<V2PayjoinProposal>, PayjoinError> {
        match self.0.clone().finalize_proposal(
            |psbt| {
                match process_psbt.process_psbt(Arc::new(psbt.clone().into())) {
                    Ok(e) => Ok(Psbt::from_str(e.as_str()).expect("Invalid process_psbt ")),
                    Err(e) => Err(PdkError::Server(e.into())),
                }
            },
            min_feerate_sat_per_vb.map(|x| (*x).into()),
        ) {
            Ok(e) => Ok(Arc::new( V2PayjoinProposal(e))),
            Err(e) => Err(e.into()),
        }
    }
}
pub struct V2PayjoinProposal(payjoin::receive::v2::PayjoinProposal);
impl From<payjoin::receive::v2::PayjoinProposal> for V2PayjoinProposal {
    fn from(value: payjoin::receive::v2::PayjoinProposal) -> Self {
        Self(value)
    }
}
impl V2PayjoinProposal{
    pub fn utxos_to_be_locked(&self) -> Vec<OutPoint> {
        let mut outpoints: Vec<OutPoint> = Vec::new();
        for e in self.0.utxos_to_be_locked() {
            outpoints.push((e.to_owned()).into())
        }
        outpoints
    }
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.0.is_output_substitution_disabled()
    }
    pub fn owned_vouts(&self) -> Vec<u64> {
        self.0.owned_vouts().iter().map(|x| *x as u64).collect()
    }
    pub fn psbt(&self) -> Arc<PartiallySignedTransaction> {
        Arc::new(self.0.psbt().clone().into())
    }
}