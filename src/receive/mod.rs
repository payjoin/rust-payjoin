use std::str::FromStr;
use std::time::Duration;

use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::FeeRate;

use crate::bitcoin_ffi::{Network, OutPoint, Script, TxOut};
use crate::error::PayjoinError;
use crate::ohttp::OhttpKeys;
use crate::{ClientResponse, Request};

#[cfg(feature = "uniffi")]
pub mod uni;

#[derive(Clone, Debug)]
pub struct Receiver(pub payjoin::receive::v2::Receiver);
impl From<Receiver> for payjoin::receive::v2::Receiver {
    fn from(value: Receiver) -> Self {
        value.0
    }
}

impl From<payjoin::receive::v2::Receiver> for Receiver {
    fn from(value: payjoin::receive::v2::Receiver) -> Self {
        Self(value)
    }
}

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
    pub fn new(
        address: String,
        network: Network,
        directory: String,
        ohttp_keys: OhttpKeys,
        expire_after: Option<u64>,
    ) -> Result<Self, PayjoinError> {
        let address = payjoin::bitcoin::Address::from_str(address.as_str())?
            .require_network(network.into())?;
        payjoin::receive::v2::Receiver::new(
            address,
            directory,
            ohttp_keys.into(),
            expire_after.map(Duration::from_secs),
        )
        .map(Into::into)
        .map_err(Into::into)
    }

    pub fn extract_req(
        &self,
        ohttp_relay: String,
    ) -> Result<(Request, ClientResponse), PayjoinError> {
        match self.0.clone().extract_req(ohttp_relay) {
            Ok((req, ctx)) => Ok((req.into(), ctx.into())),
            Err(e) => Err(PayjoinError::V2Error { message: e.to_string() }),
        }
    }

    ///The response can either be an UncheckedProposal or an ACCEPTED message indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &self,
        body: &[u8],
        ctx: &ClientResponse,
    ) -> Result<Option<UncheckedProposal>, PayjoinError> {
        <Self as Into<payjoin::receive::v2::Receiver>>::into(self.clone())
            .process_res(body, ctx.into())
            .map(|e| e.map(|o| o.into()))
            .map_err(|e| e.into())
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri(&self) -> crate::PjUri {
        <Self as Into<payjoin::receive::v2::Receiver>>::into(self.clone()).pj_uri().into()
    }

    ///The per-session public key to use as an identifier
    pub fn id(&self) -> String {
        <Self as Into<payjoin::receive::v2::Receiver>>::into(self.clone()).id().to_string()
    }

    pub fn to_json(&self) -> Result<String, PayjoinError> {
        serde_json::to_string(&self.0).map_err(|e| e.into())
    }

    pub fn from_json(json: &str) -> Result<Self, PayjoinError> {
        let receiver = serde_json::from_str::<payjoin::receive::v2::Receiver>(json)
            .map_err(<serde_json::Error as Into<PayjoinError>>::into)?;
        Ok(receiver.into())
    }
}

#[derive(Clone)]
pub struct UncheckedProposal(payjoin::receive::v2::UncheckedProposal);

impl From<payjoin::receive::v2::UncheckedProposal> for UncheckedProposal {
    fn from(value: payjoin::receive::v2::UncheckedProposal) -> Self {
        Self(value)
    }
}

impl From<UncheckedProposal> for payjoin::receive::v2::UncheckedProposal {
    fn from(value: UncheckedProposal) -> Self {
        value.0
    }
}

impl UncheckedProposal {
    ///The Sender’s Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::encode::serialize(
            &self.0.clone().extract_tx_to_schedule_broadcast(),
        )
    }

    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<MaybeInputsOwned, PayjoinError> {
        self.0
            .clone()
            .check_broadcast_suitability(
                min_fee_rate.map(FeeRate::from_sat_per_kwu),
                |transaction| {
                    Ok(can_broadcast(&payjoin::bitcoin::consensus::encode::serialize(transaction))?)
                },
            )
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(&self) -> MaybeInputsOwned {
        self.0.clone().assume_interactive_receiver().into()
    }
}
#[derive(Clone)]
pub struct MaybeInputsOwned(payjoin::receive::v2::MaybeInputsOwned);

impl From<payjoin::receive::v2::MaybeInputsOwned> for MaybeInputsOwned {
    fn from(value: payjoin::receive::v2::MaybeInputsOwned) -> Self {
        Self(value)
    }
}

impl MaybeInputsOwned {
    pub fn check_inputs_not_owned(
        &self,
        is_owned: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<MaybeInputsSeen, PayjoinError> {
        self.0
            .clone()
            .check_inputs_not_owned(|input| Ok(is_owned(&input.to_bytes())?))
            .map_err(Into::into)
            .map(Into::into)
    }
}

#[derive(Clone)]
pub struct MaybeInputsSeen(payjoin::receive::v2::MaybeInputsSeen);

impl From<payjoin::receive::v2::MaybeInputsSeen> for MaybeInputsSeen {
    fn from(value: payjoin::receive::v2::MaybeInputsSeen) -> Self {
        Self(value)
    }
}

impl MaybeInputsSeen {
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: impl Fn(&OutPoint) -> Result<bool, PayjoinError>,
    ) -> Result<OutputsUnknown, PayjoinError> {
        self.0
            .clone()
            .check_no_inputs_seen_before(|outpoint| Ok(is_known(&(*outpoint).into())?))
            .map_err(Into::into)
            .map(Into::into)
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Clone)]
pub struct OutputsUnknown(payjoin::receive::v2::OutputsUnknown);

impl From<payjoin::receive::v2::OutputsUnknown> for OutputsUnknown {
    fn from(value: payjoin::receive::v2::OutputsUnknown) -> Self {
        Self(value)
    }
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: impl Fn(&Vec<u8>) -> Result<bool, PayjoinError>,
    ) -> Result<WantsOutputs, PayjoinError> {
        self.0
            .clone()
            .identify_receiver_outputs(|input| Ok(is_receiver_output(&input.to_bytes())?))
            .map_err(Into::into)
            .map(Into::into)
    }
}

pub struct WantsOutputs(payjoin::receive::v2::WantsOutputs);

impl From<payjoin::receive::v2::WantsOutputs> for WantsOutputs {
    fn from(value: payjoin::receive::v2::WantsOutputs) -> Self {
        Self(value)
    }
}

impl WantsOutputs {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.0.is_output_substitution_disabled()
    }

    pub fn replace_receiver_outputs(
        &self,
        replacement_outputs: Vec<TxOut>,
        drain_script: &Script,
    ) -> Result<WantsOutputs, PayjoinError> {
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
    ) -> Result<WantsOutputs, PayjoinError> {
        self.0
            .clone()
            .substitute_receiver_script(&output_script.0)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_outputs(&self) -> WantsInputs {
        self.0.clone().commit_outputs().into()
    }
}

pub struct WantsInputs(payjoin::receive::v2::WantsInputs);

impl From<payjoin::receive::v2::WantsInputs> for WantsInputs {
    fn from(value: payjoin::receive::v2::WantsInputs) -> Self {
        Self(value)
    }
}
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
        candidate_inputs: Vec<InputPair>,
    ) -> Result<InputPair, PayjoinError> {
        match self.0.clone().try_preserving_privacy(candidate_inputs.into_iter().map(Into::into)) {
            Ok(t) => Ok(t.into()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contribute_inputs(
        &self,
        replacement_inputs: Vec<InputPair>,
    ) -> Result<WantsInputs, PayjoinError> {
        self.0
            .clone()
            .contribute_inputs(replacement_inputs.into_iter().map(Into::into))
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_inputs(&self) -> ProvisionalProposal {
        self.0.clone().commit_inputs().into()
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
    ) -> Result<Self, PayjoinError> {
        Ok(Self(payjoin::receive::InputPair::new(txin.into(), psbtin.into())?))
    }
}

impl From<InputPair> for payjoin::receive::InputPair {
    fn from(value: InputPair) -> Self {
        value.0
    }
}

impl From<payjoin::receive::InputPair> for InputPair {
    fn from(value: payjoin::receive::InputPair) -> Self {
        Self(value)
    }
}

pub struct ProvisionalProposal(pub payjoin::receive::v2::ProvisionalProposal);

impl From<payjoin::receive::v2::ProvisionalProposal> for ProvisionalProposal {
    fn from(value: payjoin::receive::v2::ProvisionalProposal) -> Self {
        Self(value)
    }
}

impl ProvisionalProposal {
    pub fn finalize_proposal(
        &self,
        process_psbt: impl Fn(String) -> Result<String, PayjoinError>,
        min_feerate_sat_per_vb: Option<u64>,
        max_effective_fee_rate_sat_per_vb: Option<u64>,
    ) -> Result<PayjoinProposal, PayjoinError> {
        self.0
            .clone()
            .finalize_proposal(
                |pre_processed| {
                    let psbt = process_psbt(pre_processed.to_string())?;
                    Ok(Psbt::from_str(&psbt)?)
                },
                min_feerate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
                max_effective_fee_rate_sat_per_vb.and_then(FeeRate::from_sat_per_vb),
            )
            .map(Into::into)
            .map_err(Into::into)
    }
}

#[derive(Clone)]
pub struct PayjoinProposal(pub payjoin::receive::v2::PayjoinProposal);

impl From<PayjoinProposal> for payjoin::receive::v2::PayjoinProposal {
    fn from(value: PayjoinProposal) -> Self {
        value.0
    }
}

impl From<payjoin::receive::v2::PayjoinProposal> for PayjoinProposal {
    fn from(value: payjoin::receive::v2::PayjoinProposal) -> Self {
        Self(value)
    }
}

impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> Vec<OutPoint> {
        let mut outpoints: Vec<OutPoint> = Vec::new();
        for o in
            <PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
                .utxos_to_be_locked()
        {
            outpoints.push((*o).into());
        }
        outpoints
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        <PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .is_output_substitution_disabled()
    }

    pub fn psbt(&self) -> String {
        <PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .psbt()
            .clone()
            .to_string()
    }

    pub fn extract_v2_req(
        &self,
        ohttp_relay: String,
    ) -> Result<(Request, ClientResponse), PayjoinError> {
        match self.0.clone().extract_v2_req(ohttp_relay) {
            Ok((req, ctx)) => Ok((req.into(), ctx.into())),
            Err(e) => Err(PayjoinError::V2Error { message: e.to_string() }),
        }
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
    ) -> Result<(), PayjoinError> {
        <PayjoinProposal as Into<payjoin::receive::v2::PayjoinProposal>>::into(self.clone())
            .process_res(body, ohttp_context.into())
            .map_err(|e| e.into())
    }
}

// #[cfg(test)]
// #[cfg(not(feature = "uniffi"))]
// mod test {
//     use std::sync::Arc;

//     use super::*;

//     fn get_proposal_from_test_vector() -> Result<UncheckedProposal, PayjoinError> {
//         // OriginalPSBT Test Vector from BIP
//         // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
//         // |-----------------|-----------------------|------------------------------|-------------------------|
//         // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
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
