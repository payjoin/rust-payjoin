use std::{ sync::Mutex, str::FromStr };
use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use bitcoin::psbt;

use crate::error::Error;

pub struct PartiallySignedTransaction {
    pub(crate) internal: Mutex<psbt::PartiallySignedTransaction>,
}
impl PartiallySignedTransaction {
    pub(crate) fn new(psbt_base64: String) -> Result<Self, Error> {
        let psbt: psbt::PartiallySignedTransaction = psbt::PartiallySignedTransaction::from_str(
            &psbt_base64
        )?;
        Ok(PartiallySignedTransaction {
            internal: Mutex::new(psbt),
        })
    }
}
pub struct Transaction {
    pub(crate) internal: BitcoinTransaction,
}

// impl From<Transaction> for BitcoinTransaction {
//     fn from(value: Transaction) -> Self {
//         BitcoinTransaction::
//     }
// }
