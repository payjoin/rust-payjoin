use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::FeeRate;
use payjoin::receive as pdk;

use crate::error::PayjoinError;
use crate::types::{OutPoint, TxOut};

pub trait CanBroadcast {
    fn callback(&self, tx: Vec<u8>) -> Result<bool, PayjoinError>;
}

#[derive(Clone)]
pub struct Headers(pub HashMap<String, String>);

impl Headers {
    pub fn from_vec(body: Vec<u8>) -> Self {
        let mut h = HashMap::new();
        h.insert("content-type".to_string(), "text/plain".to_string());
        h.insert("content-length".to_string(), body.len().to_string());
        Headers(h)
    }
    pub fn get_map(&self) -> HashMap<String, String> {
        self.0.clone()
    }
}

impl payjoin::receive::Headers for Headers {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|e| e.as_str())
    }
}

/// The sender’s original PSBT and optional parameters
///
/// This type is used to proces the request. It is returned by UncheckedProposal::from_request().
///
/// If you are implementing an interactive payment processor, you should get extract the original transaction with get_transaction_to_schedule_broadcast() and schedule, followed by checking that the transaction can be broadcast with check_can_broadcast. Otherwise it is safe to call assume_interactive_receive to proceed with validation.
#[derive(Clone)]
pub struct UncheckedProposal(payjoin::receive::UncheckedProposal);

impl From<payjoin::receive::UncheckedProposal> for UncheckedProposal {
    fn from(value: payjoin::receive::UncheckedProposal) -> Self {
        Self(value)
    }
}

impl UncheckedProposal {
    pub fn from_request(
        body: Vec<u8>,
        query: String,
        headers: Arc<Headers>,
    ) -> Result<Self, PayjoinError> {
        payjoin::receive::UncheckedProposal::from_request(
            body.as_slice(),
            query.as_str(),
            (*headers).clone(),
        )
        .map(|e| e.into())
        .map_err(Into::into)
    }

    /// The Sender’s Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::encode::serialize(
            &self.0.clone().extract_tx_to_schedule_broadcast(),
        )
    }

    #[cfg(feature = "uniffi")]
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
            .check_broadcast_suitability(
                min_fee_rate.map(|x| FeeRate::from_sat_per_kwu(x)),
                |transaction| {
                    can_broadcast
                        .callback(payjoin::bitcoin::consensus::encode::serialize(transaction))
                        .map_err(|e| payjoin::receive::Error::Server(e.into()))
                },
            )
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<Arc<MaybeInputsOwned>, PayjoinError> {
        self.0
            .clone()
            .check_broadcast_suitability(
                min_fee_rate.map(|x| FeeRate::from_sat_per_kwu(x)),
                |transaction| {
                    can_broadcast(&payjoin::bitcoin::consensus::encode::serialize(transaction))
                        .map_err(|e| payjoin::receive::Error::Server(e.into()))
                },
            )
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver requires manual intervention, as in most consumer wallets.
    ///
    /// So-called “non-interactive” receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks. Those receivers call get_transaction_to_check_broadcast() and attest_tested_and_scheduled_broadcast() after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> Arc<MaybeInputsOwned> {
        Arc::new(self.0.clone().assume_interactive_receiver().into())
    }
}

/// Type state to validate that the Original PSBT has no receiver-owned inputs.
/// Call check_no_receiver_owned_inputs() to proceed.
#[derive(Clone)]
pub struct MaybeInputsOwned(pdk::MaybeInputsOwned);

impl From<pdk::MaybeInputsOwned> for MaybeInputsOwned {
    fn from(value: pdk::MaybeInputsOwned) -> Self {
        Self(value)
    }
}

pub trait IsScriptOwned {
    fn callback(&self, script: Vec<u8>) -> Result<bool, PayjoinError>;
}

impl MaybeInputsOwned {
    #[cfg(feature = "uniffi")]
    ///Check that the Original PSBT has no receiver-owned inputs. Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<MaybeMixedInputScripts>, PayjoinError> {
        self.0
            .clone()
            .check_inputs_not_owned(|input| {
                is_owned
                    .callback(input.to_bytes())
                    .map_err(|e| payjoin::receive::Error::Server(e.into()))
            })
            .map_err(|e| e.into())
            .map(|e| Arc::new(e.into()))
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn check_inputs_not_owned(
        &self,
        is_owned: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<Arc<MaybeMixedInputScripts>, PayjoinError> {
        self.0
            .clone()
            .check_inputs_not_owned(|input| {
                is_owned(&input.to_bytes()).map_err(|e| payjoin::receive::Error::Server(e.into()))
            })
            .map_err(|e| e.into())
            .map(|e| Arc::new(e.into()))
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call check_no_inputs_seen to proceed.
#[derive(Clone)]
pub struct MaybeMixedInputScripts(pdk::MaybeMixedInputScripts);

impl From<pdk::MaybeMixedInputScripts> for MaybeMixedInputScripts {
    fn from(value: pdk::MaybeMixedInputScripts) -> Self {
        Self(value)
    }
}

impl MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints. This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(&self) -> Result<Arc<MaybeInputsSeen>, PayjoinError> {
        self.0
            .clone()
            .check_no_mixed_input_scripts()
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }
}

pub trait IsOutputKnown {
    fn callback(&self, outpoint: OutPoint) -> Result<bool, PayjoinError>;
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call check_no_inputs_seen to proceed.
#[derive(Clone)]
pub struct MaybeInputsSeen(pdk::MaybeInputsSeen);

impl From<pdk::MaybeInputsSeen> for MaybeInputsSeen {
    fn from(value: pdk::MaybeInputsSeen) -> Self {
        Self(value)
    }
}

impl MaybeInputsSeen {
    #[cfg(feature = "uniffi")]
    /// Make sure that the original transaction inputs have never been seen before. This prevents probing attacks. This prevents reentrant Payjoin, where a sender proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: Box<dyn IsOutputKnown>,
    ) -> Result<Arc<OutputsUnknown>, PayjoinError> {
        self.0
            .clone()
            .check_no_inputs_seen_before(|outpoint| {
                is_known.callback(outpoint.clone().into()).map_err(|e| pdk::Error::Server(e.into()))
            })
            .map_err(|e| e.into())
            .map(|e| Arc::new(e.into()))
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: impl Fn(&OutPoint) -> Result<bool, PayjoinError>,
    ) -> Result<Arc<OutputsUnknown>, PayjoinError> {
        self.0
            .clone()
            .check_no_inputs_seen_before(|outpoint| {
                is_known(&outpoint.clone().into()).map_err(|e| pdk::Error::Server(e.into()))
            })
            .map_err(|e| e.into())
            .map(|e| Arc::new(e.into()))
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money. Identify those outputs with identify_receiver_outputs() to proceed
#[derive(Clone)]
pub struct OutputsUnknown(pdk::OutputsUnknown);

impl From<pdk::OutputsUnknown> for OutputsUnknown {
    fn from(value: pdk::OutputsUnknown) -> Self {
        Self(value)
    }
}

impl OutputsUnknown {
    #[cfg(feature = "uniffi")]
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: Box<dyn IsScriptOwned>,
    ) -> Result<Arc<ProvisionalProposal>, PayjoinError> {
        self.0
            .clone()
            .identify_receiver_outputs(|output_script| {
                is_receiver_output
                    .callback(output_script.to_bytes())
                    .map_err(|e| payjoin::receive::Error::Server(e.into()))
            })
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<Arc<ProvisionalProposal>, PayjoinError> {
        self.0
            .clone()
            .identify_receiver_outputs(|input| {
                is_receiver_output(&input.to_bytes())
                    .map_err(|e| payjoin::receive::Error::Server(e.into()))
            })
            .map_err(|e| e.into())
            .map(|e| Arc::new(e.into()))
    }
}

///A mutable checked proposal that the receiver may contribute inputs to make a payjoin.
pub struct ProvisionalProposal(Mutex<pdk::ProvisionalProposal>);

impl From<pdk::ProvisionalProposal> for ProvisionalProposal {
    fn from(value: pdk::ProvisionalProposal) -> Self {
        Self(Mutex::new(value))
    }
}

pub trait ProcessPartiallySignedTransaction {
    fn callback(&self, psbt: String) -> Result<String, PayjoinError>;
}

impl ProvisionalProposal {
    fn mutex_guard(&self) -> MutexGuard<'_, payjoin::receive::ProvisionalProposal> {
        self.0.lock().unwrap()
    }
    #[cfg(not(feature = "uniffi"))]
    ///If output substitution is enabled, replace the receiver’s output script with a new one.
    pub fn try_substitute_receiver_output(
        &self,
        generate_script: impl Fn() -> Result<Vec<u8>, PayjoinError>,
    ) -> Result<(),PayjoinError>{
        self.mutex_guard()
            .try_substitute_receiver_output(|| generate_script()
                .map(|e| payjoin::bitcoin::ScriptBuf::from_bytes(e))
                .map_err(|e|  payjoin::Error::Server(e.into())))
            .map_err(|e| e.into())
    }
    #[cfg(feature = "uniffi")]
    pub fn try_substitute_receiver_output(
        &self,
        generate_script: impl Fn() -> Result<Vec<u8>, PayjoinError>,
    ) -> Result<(),PayjoinError>{

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

    /// Select receiver input such that the payjoin avoids surveillance. Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions. To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH “Unnecessary input heuristic” is one class of them to avoid. We define UIH1 and UIH2 according to the BlockSci practice BlockSci UIH1 and UIH2:
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: HashMap<u64, OutPoint>,
    ) -> Result<OutPoint, PayjoinError> {
        let candidate_inputs: HashMap<payjoin::bitcoin::Amount, payjoin::bitcoin::OutPoint> =
            candidate_inputs
                .into_iter()
                .map(|(key, value)| (payjoin::bitcoin::Amount::from_sat(key), value.into()))
                .collect();
        self.mutex_guard()
            .try_preserving_privacy(candidate_inputs)
            .map_err(|e| PayjoinError::SelectionError { message: format!("{:?}", e) })
            .map(|o| o.into())
    }
    #[cfg(feature = "uniffi")]
    pub fn finalize_proposal(
        &self,
        process_psbt: Box<dyn ProcessPartiallySignedTransaction>,
        min_feerate_sat_per_vb: Option<u64>,
    ) -> Result<Arc<PayjoinProposal>, PayjoinError> {
        self.mutex_guard()
            .clone()
            .finalize_proposal(
                |psbt| {
                    process_psbt
                        .callback(psbt.to_string())
                        .map(|e| Psbt::from_str(e.as_str()).expect("Invalid process_psbt "))
                        .map_err(|e| pdk::Error::Server(e.into()))
                },
                min_feerate_sat_per_vb.and_then(|x| FeeRate::from_sat_per_vb(x)),
            )
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn finalize_proposal(
        &self,
        process_psbt: impl Fn(String) -> Result<String, PayjoinError>,
        min_feerate_sat_per_vb: Option<u64>,
    ) -> Result<Arc<PayjoinProposal>, PayjoinError> {
        self.mutex_guard()
            .clone()
            .finalize_proposal(
                |psbt| {
                    process_psbt(psbt.to_string())
                        .map(|e| Psbt::from_str(e.as_str()).expect("Invalid process_psbt "))
                        .map_err(|e| pdk::Error::Server(e.into()))
                },
                min_feerate_sat_per_vb.and_then(|x| FeeRate::from_sat_per_vb(x)),
            )
            .map(|e| Arc::new(e.into()))
            .map_err(|e| e.into())
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[derive(Clone)]
pub struct PayjoinProposal(pdk::PayjoinProposal);

impl From<pdk::PayjoinProposal> for PayjoinProposal {
    fn from(value: pdk::PayjoinProposal) -> Self {
        Self(value)
    }
}
impl From<PayjoinProposal> for pdk::PayjoinProposal {
    fn from(value: PayjoinProposal) -> Self {
        value.0
    }
}

impl PayjoinProposal {
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
    pub fn psbt(&self) -> String {
        self.0.psbt().to_string()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    fn get_proposal_from_test_vector() -> Result<UncheckedProposal, PayjoinError> {
        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt =
            "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
        let body = original_psbt.as_bytes();

        let headers = Headers::from_vec(body.to_vec());
        UncheckedProposal::from_request(
            body.to_vec(),
            "?maxadditionalfeecontribution=182?additionalfeeoutputindex=0".to_string(),
            Arc::new(headers),
        )
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = get_proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        let proposal = get_proposal_from_test_vector().unwrap();
        let _payjoin = proposal
            .assume_interactive_receiver()
            .clone()
            .check_inputs_not_owned(|_| Ok(true))
            .expect("No inputs should be owned")
            .check_no_mixed_input_scripts()
            .expect("No mixed input scripts")
            .check_no_inputs_seen_before(|_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(|script| {
                let network = payjoin::bitcoin::Network::Bitcoin;
                let script = payjoin::bitcoin::ScriptBuf::from_bytes(script.to_vec());
                Ok(payjoin::bitcoin::Address::from_script(&script, network)
                    == payjoin::bitcoin::Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
                        .map(|x| x.require_network(network).expect("Invalid address")))
            })
            .expect("Receiver output should be identified");
    }
}
