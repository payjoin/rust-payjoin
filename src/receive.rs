use payjoin::receive::{
    MaybeInputsOwned as PdkMaybeInputsOwned,
    MaybeMixedInputScripts as PdkMaybeMixedInputScripts,
    MaybeInputsSeen as PdkMaybeInputsSeen,
    OutputsUnknown as PdkOutputsUnknown,
    PayjoinProposal as PdkPayjoinProposal,
    UncheckedProposal as PdkUncheckedProposal,
    RequestError,
};
use crate::{
    PdkError,
    transaction::{ Transaction, PartiallySignedTransaction },
    Address,
    OutPoint,
    Script,
    TxOut,
};
use anyhow::anyhow;

pub struct UncheckedProposal {
    pub internal: PdkUncheckedProposal,
}
pub trait CanBroadcast {
    fn test_mempool_accept(
        &self,
        tx_hex: Vec<String>
    ) -> Result<
        Vec<bitcoincore_rpc::bitcoincore_rpc_json::TestMempoolAcceptResult>,
        bitcoincore_rpc::Error
    >;
}
pub struct Headers {
    pub length: String,
}

impl Headers {
    pub fn new(length: u64) -> Headers {
        Headers { length: length.to_string() }
    }
}

impl payjoin::receive::Headers for Headers {
    fn get_header(&self, key: &str) -> Option<&str> {
        match key {
            "content-length" => Some(&self.length),
            "content-type" => Some("text/plain"),
            _ => None,
        }
    }
}

impl UncheckedProposal {
    pub fn from_request(
        //TODO; Find which type that implement Read trait is an appropriate option
        body: impl std::io::Read,
        query: String,
        headers: Headers
    ) -> Result<Self, PdkError> {
        let res = PdkUncheckedProposal::from_request(body, query.as_str(), headers)?;
        Ok(UncheckedProposal { internal: res })
    }
    // fn get_internal(&self) -> MutexGuard<PdkUncheckedProposal> {
    //     self.internal.lock().expect("PdkUncheckedProposal")
    // }
    pub fn get_transaction_to_schedule_broadcast(&self) -> Transaction {
        let res = self.internal.get_transaction_to_schedule_broadcast();
        Transaction { internal: res }
    }
    pub fn check_can_broadcast(
        self,
        can_broadcast: Box<dyn CanBroadcast>
    ) -> Result<MaybeInputsOwned, PdkError> {
        let res = self.internal.check_can_broadcast(|tx| {
            let raw_tx = hex::encode(bitcoin::consensus::encode::serialize(&tx));
            let mempool_results = can_broadcast
                .test_mempool_accept(vec![raw_tx])
                .map_err(|e| PdkError::Server(e.into()))?;
            match mempool_results.first() {
                Some(result) => Ok(result.allowed),
                None =>
                    Err(
                        PdkError::Server(
                            anyhow!("No mempool results returned on broadcast check").into()
                        )
                    ),
            }
        })?;
        Ok(MaybeInputsOwned { internal: res })
    }
}

///Typestate to validate that the Original PSBT has no receiver-owned inputs.

///Call check_no_receiver_owned_inputs() to proceed.
pub struct MaybeInputsOwned {
    pub internal: PdkMaybeInputsOwned,
}

pub trait IsScriptOwned {
    fn is_owned(&self, script: Script) -> Result<bool, PdkError>;
}
impl MaybeInputsOwned {
    ///Check that the Original PSBT has no receiver-owned inputs. Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.

    ///An attacker could try to spend receiver’s own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: Box<dyn IsScriptOwned>
    ) -> Result<MaybeMixedInputScripts, PdkError> {
        match
            self.internal.check_inputs_not_owned(|input|
                is_owned.is_owned(Script { inner: input.to_bytes() })
            )
        {
            Ok(e) => Ok(MaybeMixedInputScripts { internal: e }),
            Err(e) => Err(e),
        }
    }
}
///Typestate to validate that the Original PSBT has no inputs that have been seen before.
///Call check_no_inputs_seen to proceed.
pub struct MaybeMixedInputScripts {
    pub internal: PdkMaybeMixedInputScripts,
}
impl MaybeMixedInputScripts {
    ///Verify the original transaction did not have mixed input types Call this after checking downstream.
    ///Note: mixed spends do not necessarily indicate distinct wallet fingerprints. This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(
        self
    ) -> Result<MaybeInputsSeen, payjoin::receive::RequestError> {
        match self.internal.check_no_mixed_input_scripts() {
            Ok(e) => Ok(MaybeInputsSeen { internal: e }),
            Err(e) => Err(e),
        }
    }
}
///Typestate to validate that the Original PSBT has no inputs that have been seen before.

///Call check_no_inputs_seen to proceed.
pub struct MaybeInputsSeen {
    pub internal: PdkMaybeInputsSeen,
}
pub trait IsOutoutKnown {
    fn is_known(&self, outpoint: OutPoint) -> Result<bool, PdkError>;
}
impl MaybeInputsSeen {
    pub fn check_no_inputs_seen_before(
        self,
        is_known: Box<dyn IsOutoutKnown>
    ) -> Result<OutputsUnknown, PdkError> {
        match
            self.internal.check_no_inputs_seen_before(|outpoint|
                is_known.is_known(outpoint.to_owned().into())
            )
        {
            Ok(e) => Ok(OutputsUnknown { internal: e }),
            Err(e) => Err(e),
        }
    }
}

///The receiver has not yet identified which outputs belong to the receiver.
///Only accept PSBTs that send us money. Identify those outputs with identify_receiver_outputs() to proceed
pub struct OutputsUnknown {
    pub internal: PdkOutputsUnknown,
}

impl OutputsUnknown {
    ///Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: Box<dyn IsScriptOwned>
    ) -> Result<PayjoinProposal, PdkError> {
        match
            self.internal.identify_receiver_outputs(|output_script|
                is_receiver_output.is_owned(Script { inner: output_script.to_bytes() })
            )
        {
            Ok(e) => Ok(PayjoinProposal { internal: e }),
            Err(e) => Err(e),
        }
    }
}

///A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
pub struct PayjoinProposal {
    pub internal: PdkPayjoinProposal,
}
impl PayjoinProposal {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.internal.is_output_substitution_disabled()
    }

    pub fn contribute_witness_input(&mut self, txout: TxOut, outpoint: OutPoint) {
        self.internal.contribute_witness_input(txout.into(), outpoint.into())
    }
    pub fn contribute_non_witness_input(&mut self, tx: Transaction, outpoint: OutPoint) {
        self.internal.contribute_non_witness_input(tx.internal, outpoint.into())
    }
    pub fn substitute_output_address(&mut self, substitute_address: Address) {
        self.internal.substitute_output_address(substitute_address.internal)
    }

    ///Apply additional fee contribution now that the receiver has contributed input this is kind of a “build_proposal” step before we sign and finalize and extract

    ///WARNING: DO NOT ALTER INPUTS OR OUTPUTS AFTER THIS STEP
    pub fn apply_fee(
        &mut self,
        min_feerate_sat_per_vb: Option<u64>
    ) -> Result<PartiallySignedTransaction, RequestError> {
        match self.internal.apply_fee(min_feerate_sat_per_vb) {
            Ok(e) => Ok(PartiallySignedTransaction { internal: e.to_owned() }),
            Err(e) => Err(e),
        }
    }
    ///Return a Payjoin Proposal PSBT that the sender will find acceptable.
    ///This attempts to calculate any network fee owed by the receiver, subtract it from their output, and return a PSBT that can produce a consensus-valid transaction that the sender will accept.
    ///wallet_process_psbt should sign and finalize receiver inputs
    pub fn prepare_psbt(
        self,
        processed_psbt: PartiallySignedTransaction
    ) -> Result<PartiallySignedTransaction, RequestError> {
        match self.internal.prepare_psbt(processed_psbt.internal.to_owned()) {
            Ok(e) => Ok(PartiallySignedTransaction { internal: e.to_owned() }),
            Err(e) => Err(e),
        }
    }
}
