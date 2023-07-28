use std::sync::Mutex;

use bitcoin::Script;
use payjoin::receive::{
    MaybeInputsOwned as PdkMaybeInputsOwned,
    MaybeMixedInputScripts as PdkMaybeMixedInputScripts,
    MaybeInputsSeen as PdkMaybeInputsSeen,
    OutputsUnknown as PdkOutputsUnknown,
    PayjoinProposal as PdkPayjoinProposal,
    UncheckedProposal as PdkUncheckedProposal,
    Headers,
};
use crate::{ PdkError, transaction::Transaction };
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
impl UncheckedProposal {
    pub fn from_request(
        body: impl std::io::Read,
        query: String,
        headers: impl Headers
    ) -> Result<Self, PdkError> {
        let res = PdkUncheckedProposal::from_request(body, query.as_str(), headers)?;
        Ok(UncheckedProposal { internal: res })
    }
    // fn get_internal(&self) -> MutexGuard<PdkUncheckedProposal> {
    //     self.internal.lock().expect("PdkUncheckedProposal")
    // }
    pub fn get_transaction_to_schedule_broadcast(&self) -> Transaction {
        let res = self.internal.get_transaction_to_schedule_broadcast();
        Transaction { internal: Mutex::new(res) }
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

pub struct MaybeInputsOwned {
    pub internal: PdkMaybeInputsOwned,
}

pub trait IsScriptOwned {
    fn is_owned(&self, script: &Script) -> Result<bool, PdkError>;
}
impl MaybeInputsOwned {
    pub fn check_inputs_not_owned(
        self,
        is_owned: Box<dyn IsScriptOwned>
    ) -> Result<MaybeMixedInputScripts, PdkError> {
        match self.internal.check_inputs_not_owned(|input| is_owned.is_owned(input)) {
            Ok(e) => Ok(MaybeMixedInputScripts { internal: e }),
            Err(e) => Err(e),
        }
    }
}
pub struct MaybeMixedInputScripts {
    pub internal: PdkMaybeMixedInputScripts,
}
///Typestate to validate that the Original PSBT has no inputs that have been seen before.
///Call check_no_inputs_seen to proceed.
pub struct MaybeInputsSeen {
    pub internal: PdkMaybeInputsSeen,
}

impl MaybeInputsSeen {}

///The receiver has not yet identified which outputs belong to the receiver.
///Only accept PSBTs that send us money. Identify those outputs with identify_receiver_outputs() to proceed
pub struct OutputsUnknown {
    pub internal: PdkOutputsUnknown,
}

impl OutputsUnknown {}

///A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
pub struct PayjoinProposal {
    pub internal: PdkPayjoinProposal,
}
impl PayjoinProposal {
    // pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &OutPoint> {}
}
