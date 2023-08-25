use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use payjoin::bitcoin::psbt::PartiallySignedTransaction as BitcoinPsbt;
use std::{str::FromStr, sync::Arc};

use crate::error::Error;
#[derive(Debug, Clone)]
pub struct PartiallySignedTransaction {
	pub internal: Arc<BitcoinPsbt>,
}
impl PartiallySignedTransaction {
	pub fn new(psbt_base64: String) -> Result<Self, Error> {
		let psbt: BitcoinPsbt = BitcoinPsbt::from_str(&psbt_base64)?;
		Ok(PartiallySignedTransaction { internal: Arc::new(psbt) })
	}
	pub fn serialize(&self) -> Vec<u8> {
		self.internal.serialize()
	}
}
pub struct Transaction {
	pub(crate) internal: BitcoinTransaction,
}
