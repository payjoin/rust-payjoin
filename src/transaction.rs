use std::{io::Cursor, str::FromStr, sync::Arc};

use payjoin::bitcoin::psbt::PartiallySignedTransaction as BitcoinPsbt;
use payjoin::bitcoin::{
	blockdata::transaction::Transaction as BitcoinTransaction, consensus::Decodable,
};

use crate::error::PayjoinError;

///
/// Partially signed transaction, commonly referred to as a PSBT.
#[derive(Debug, Clone)]
pub struct PartiallySignedTransaction(BitcoinPsbt);

impl From<BitcoinPsbt> for PartiallySignedTransaction {
	fn from(value: BitcoinPsbt) -> Self {
		PartiallySignedTransaction(value)
	}
}

impl From<PartiallySignedTransaction> for BitcoinPsbt {
	fn from(value: PartiallySignedTransaction) -> Self {
		value.0
	}
}

impl PartiallySignedTransaction {
	pub fn from_string(psbt_base64: String) -> Result<Self, PayjoinError> {
		let psbt = BitcoinPsbt::from_str(&psbt_base64)?;
		Ok(PartiallySignedTransaction(psbt))
	}

	pub fn serialize(&self) -> Vec<u8> {
		self.0.serialize()
	}

	pub fn extract_tx(&self) -> Arc<Transaction> {
		Arc::new(self.0.clone().extract_tx().into())
	}
	pub fn as_string(&self) -> String {
		self.0.to_string()
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
	pub fn serialize(&self) -> Vec<u8> {
		payjoin::bitcoin::consensus::serialize(&self.internal)
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

pub struct Txid(String);

impl Txid {
	pub fn as_string(&self) -> String {
		self.0.clone()
	}
}
