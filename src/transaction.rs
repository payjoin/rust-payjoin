use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use bitcoin::psbt::PartiallySignedTransaction as BitcoinPsbt;
use std::{str::FromStr, sync::Mutex};

use crate::error::Error;

pub struct PartiallySignedTransaction {
	pub(crate) internal: BitcoinPsbt,
}
impl PartiallySignedTransaction {
	pub(crate) fn new(psbt_base64: String) -> Result<Self, Error> {
		let psbt: BitcoinPsbt = BitcoinPsbt::from_str(&psbt_base64)?;
		Ok(PartiallySignedTransaction { internal: psbt })
	}
}
pub struct Transaction {
	pub(crate) internal: BitcoinTransaction,
}
