use anyhow::Ok;
use payjoin::receive::{
    MaybeInputsOwned as PdkMaybeInputsOwned,
    MaybeMixedInputScripts as PdkMaybeMixedInputScripts,
    MaybeInputsSeen as PdkMaybeInputsSeen,
    OutputsUnknown as PdkOutputsUnknown,
    PayjoinProposal as PdkPayjoinProposal,
    UncheckedProposal as PdkUncheckedProposal,
    Headers,
};
use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use crate::{ bitcoind::OutPoint, error::Error, transaction::Transaction };

pub struct MaybeInputsOwned {
    pub internal: PdkMaybeInputsOwned,
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

pub struct UncheckedProposal {
    pub internal: PdkUncheckedProposal,
}

// impl UncheckedProposal {
//     pub fn from_request(
//         body: impl std::io::Read,
//         query: String,
//         headers: impl Headers
//     ) -> Result<Self, Error> {
//         let res = PdkUncheckedProposal::from_request(body, query.as_str(), headers)?;
//         Ok(UncheckedProposal { internal: res })
//     }
//     pub fn get_transaction_to_schedule_broadcast(&self) -> Transaction {
//         let res = self.internal.get_transaction_to_schedule_broadcast();
//         Transaction { internal: res }
//     }
//     // pub fn check_can_broadcast(
//     //     self,
//     //     can_broadcast: impl Fn(&BitcoinTransaction) -> Result<bool, payjoin::receive::Error>
//     // ) -> Result<MaybeInputsOwned, Error> {
//     //     let res = self.internal.check_can_broadcast(can_broadcast)?;
//     //     Ok(MaybeInputsOwned { internal: res })
//     // }
// }
