use std::{ sync::Mutex, str::FromStr };
use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use bitcoin::psbt::PartiallySignedTransaction as BitcoinPsbt;

use crate::error::Error;

pub struct PartiallySignedTransaction {
    pub(crate) internal: Mutex<BitcoinPsbt>,
}
impl PartiallySignedTransaction {
    pub(crate) fn new(psbt_base64: String) -> Result<Self, Error> {
        let psbt: BitcoinPsbt = BitcoinPsbt::from_str(&psbt_base64)?;
        Ok(PartiallySignedTransaction {
            internal: Mutex::new(psbt),
        })
    }
}
pub struct Transaction {
    pub(crate) internal: Mutex<BitcoinTransaction>,
}
