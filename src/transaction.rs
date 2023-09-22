use payjoin::bitcoin::psbt::PartiallySignedTransaction as BitcoinPsbt;
use payjoin::bitcoin::{
	blockdata::transaction::Transaction as BitcoinTransaction, consensus::Decodable,
};
use std::{io::Cursor, str::FromStr, sync::Arc};

use crate::{error::PayjoinError, send::Context};

///
/// Partially signed transaction, commonly referred to as a PSBT.
#[derive(Debug, Clone)]
pub struct PartiallySignedTransaction {
	internal: BitcoinPsbt,
}
impl From<BitcoinPsbt> for PartiallySignedTransaction {
	fn from(value: BitcoinPsbt) -> Self {
		PartiallySignedTransaction { internal: value }
	}
}
impl From<PartiallySignedTransaction> for BitcoinPsbt {
	fn from(value: PartiallySignedTransaction) -> Self {
		value.internal
	}
}
impl PartiallySignedTransaction {
	pub fn new(psbt_base64: String) -> Result<Self, PayjoinError> {
		let psbt = BitcoinPsbt::from_str(&psbt_base64)?;
		Ok(PartiallySignedTransaction { internal: psbt })
	}
	///Decodes and validates the response.

	///Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
	pub fn process_response(context: Arc<Context>, response: String) -> Result<Self, PayjoinError> {
		let ctx: payjoin::send::Context = match Arc::try_unwrap(context) {
			Ok(e) => e.into(),
			Err(_) => panic!("Context preproses failed"),
		};
		match ctx.process_response(&mut response.as_bytes()) {
			Ok(e) => Ok(PartiallySignedTransaction { internal: e }),
			Err(e) => Err(PayjoinError::UnexpectedError { message: e.to_string() }),
		}
	}
	pub fn serialize(&self) -> Vec<u8> {
		self.internal.serialize()
	}
}

#[derive(Clone)]
pub struct Transaction {
	internal: BitcoinTransaction,
}
impl Transaction {
	pub fn new(transaction_bytes: Vec<u8>) -> Result<Self, PayjoinError> {
		let mut decoder = Cursor::new(transaction_bytes);
		match BitcoinTransaction::consensus_decode(&mut decoder) {
			Ok(e) => Ok(e.into()),
			Err(e) => Err(PayjoinError::TransactionError { message: e.to_string() }),
		}
	}
	pub fn txid(&self) -> Arc<Txid> {
		Arc::new(Txid(self.internal.txid().to_string()))
	}
}
pub struct Txid(String);
impl Txid {
	pub fn to_string(&self) -> String {
		self.0.clone()
	}
}
impl From<Transaction> for BitcoinTransaction {
	fn from(value: Transaction) -> Self {
		value.internal
	}
}
impl From<BitcoinTransaction> for Transaction {
	fn from(value: BitcoinTransaction) -> Self {
		Self { internal: value }
	}
}
