#![crate_name = "pdk_ffi"]
mod error;
mod receive;
mod send;
#[cfg(test)]
mod test;
mod transaction;
mod uri;
use crate::receive::{
	CanBroadcast, Headers, MaybeInputsOwned, MaybeInputsSeen, MaybeMixedInputScripts,
	OutputsUnknown, PayjoinProposal, UncheckedProposal,
};
use crate::send::{Configuration, Context, Request};

use crate::transaction::{PartiallySignedTransaction, Transaction, Txid};
use crate::uri::{Amount, PrjUri, PrjUriRequest, Uri, Url};
pub use error::Error;
pub use payjoin::bitcoin;
use payjoin::bitcoin::{Address as BitcoinAdrress, ScriptBuf as BitcoinScriptBuf};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
uniffi::include_scaffolding!("pdk_ffi");

/// A reference to a transaction output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
	/// The referenced transaction's txid.
	pub txid: String,
	/// The index of the referenced output in its transaction's vout.
	pub vout: u32,
}

impl From<OutPoint> for bitcoin::OutPoint {
	fn from(outpoint: OutPoint) -> Self {
		bitcoin::OutPoint {
			txid: bitcoin::Txid::from_str(&outpoint.txid).expect("Invalid txid"),
			vout: outpoint.vout,
		}
	}
}
impl From<bitcoin::OutPoint> for OutPoint {
	fn from(outpoint: bitcoin::OutPoint) -> Self {
		OutPoint { txid: outpoint.txid.to_string(), vout: outpoint.vout }
	}
}

#[derive(Debug, Clone, PartialEq)]
pub struct Address {
	internal: BitcoinAdrress,
}
impl From<bitcoin::Address> for Address {
	fn from(value: bitcoin::Address) -> Self {
		Address { internal: value }
	}
}
impl Address {
	pub fn new(address: String) -> Result<Address, Error> {
		match BitcoinAdrress::from_str(&address) {
			Ok(e) => Ok(e.assume_checked().into()),
			Err(e) => Err(Error::InvalidAddress(e.to_string())),
		}
	}
	//TODO; ADD TO .UDL
	pub fn from_script(script: Arc<ScriptBuf>, network: Network) -> Result<Self, Error> {
		match BitcoinAdrress::from_script(script.internal.as_script(), network.into()) {
			Ok(e) => Ok(e.into()),
			Err(e) => Err(Error::InvalidAddress(e.to_string())),
		}
	}
	pub fn to_string(&self) -> String {
		self.internal.to_string()
	}
}

impl From<Address> for bitcoin::Address {
	fn from(value: Address) -> Self {
		value.internal
	}
}

/// A Bitcoin script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptBuf {
	internal: BitcoinScriptBuf,
}
impl ScriptBuf {
	pub fn new(raw_output_script: Vec<u8>) -> Self {
		let buf = BitcoinScriptBuf::from_bytes(raw_output_script);
		ScriptBuf { internal: buf }
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		self.internal.to_bytes()
	}
	pub fn to_hex_string(&self) -> String {
		self.internal.to_hex_string()
	}
	pub fn to_string(&self) -> String {
		self.internal.to_string()
	}
	pub fn to_asm_string(&self) -> String {
		self.internal.to_asm_string()
	}
}
impl From<ScriptBuf> for bitcoin::ScriptBuf {
	fn from(value: ScriptBuf) -> Self {
		value.internal
	}
}
impl From<bitcoin::ScriptBuf> for ScriptBuf {
	fn from(value: bitcoin::ScriptBuf) -> Self {
		ScriptBuf { internal: value }
	}
}

#[derive(Debug)]
pub struct TxOut {
	/// The value of the output, in satoshis.
	value: u64,
	/// The address of the output.
	script_pubkey: ScriptBuf,
}
impl From<TxOut> for bitcoin::TxOut {
	fn from(tx_out: TxOut) -> Self {
		bitcoin::TxOut { value: tx_out.value, script_pubkey: tx_out.script_pubkey.internal }
	}
}

impl From<bitcoin::TxOut> for TxOut {
	fn from(tx_out: bitcoin::TxOut) -> Self {
		TxOut {
			value: tx_out.value,
			script_pubkey: ScriptBuf { internal: tx_out.script_pubkey.into() },
		}
	}
}

// pub struct Input {
//     pub txid: String,
//     pub vout: u32,
//     pub sequence: Option<u32>,
// }
// impl Input {
//     pub fn new(txid: String, vout: u32, sequence: Option<u32>) -> Self {
//         Self { txid, vout, sequence }
//     }
// }
// impl From<&Input> for bitcoincore_rpc::json::CreateRawTransactionInput {
//     fn from(value: &Input) -> Self {
//         bitcoincore_rpc::json::CreateRawTransactionInput {
//             txid: bitcoin::Txid::from_str(&value.txid).expect("Invalid Txid"),
//             vout: value.vout,
//             sequence: value.sequence,
//         }
//     }
// }

#[derive(Clone)]
pub enum Network {
	///Bitcoin’s testnet
	Testnet,
	///Bitcoin’s regtest
	Regtest,
	///Classic Bitcoin
	Bitcoin,
	///Bitcoin’s signet
	Signet,
}
impl Default for Network {
	fn default() -> Self {
		Network::Testnet
	}
}
impl From<Network> for bitcoin::Network {
	fn from(network: Network) -> Self {
		match network {
			Network::Signet => bitcoin::Network::Signet,
			Network::Testnet => bitcoin::Network::Testnet,
			Network::Regtest => bitcoin::Network::Regtest,
			Network::Bitcoin => bitcoin::Network::Bitcoin,
		}
	}
}
