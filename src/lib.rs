#![crate_name = "payjoin_ffi"]

mod error;
mod receive;
mod send;
#[cfg(test)]
mod test;
mod transaction;
mod uri;

use std::str::FromStr;
use std::sync::Arc;

use error::PayjoinError;
use payjoin::bitcoin::{Address as BitcoinAddress, ScriptBuf as BitcoinScriptBuf};
use serde::{Deserialize, Serialize};

use crate::receive::v2::{
    ClientResponse, Enrolled, ExtractReq, V2MaybeInputsOwned, V2MaybeInputsSeen,
    V2MaybeMixedInputScripts, V2OutputsUnknown, V2PayjoinProposal, V2ProvisionalProposal,
    V2UncheckedProposal,
};
use crate::receive::{
    CanBroadcast, Headers, IsOutputKnown, IsScriptOwned, MaybeInputsOwned, MaybeInputsSeen,
    MaybeMixedInputScripts, OutputsUnknown, PayjoinProposal, ProcessPartiallySignedTransaction,
    ProvisionalProposal, UncheckedProposal,
};
use crate::send::{Context, Request, RequestBuilder};
use crate::transaction::{PartiallySignedTransaction, Transaction, Txid};
use crate::uri::{Amount, PjUri, PrjUriRequest, Uri, Url};

uniffi::include_scaffolding!("payjoin_ffi");

/// A reference to a transaction output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: String,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

impl From<OutPoint> for payjoin::bitcoin::OutPoint {
    fn from(outpoint: OutPoint) -> Self {
        payjoin::bitcoin::OutPoint {
            txid: payjoin::bitcoin::Txid::from_str(&outpoint.txid).expect("Invalid txid"),
            vout: outpoint.vout,
        }
    }
}

impl From<payjoin::bitcoin::OutPoint> for OutPoint {
    fn from(outpoint: payjoin::bitcoin::OutPoint) -> Self {
        OutPoint { txid: outpoint.txid.to_string(), vout: outpoint.vout }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    internal: BitcoinAddress,
}

impl From<payjoin::bitcoin::Address> for Address {
    fn from(value: payjoin::bitcoin::Address) -> Self {
        Address { internal: value }
    }
}

impl Address {
    pub fn new(address: String) -> Result<Address, PayjoinError> {
        match BitcoinAddress::from_str(&address) {
            Ok(e) => Ok(e.assume_checked().into()),
            Err(e) => Err(PayjoinError::InvalidAddress { message: e.to_string() }),
        }
    }

    pub fn from_script(script: Arc<ScriptBuf>, network: Network) -> Result<Self, PayjoinError> {
        match BitcoinAddress::from_script(script.internal.as_script(), network.into()) {
            Ok(e) => Ok(e.into()),
            Err(e) => Err(PayjoinError::InvalidScript { message: e.to_string() }),
        }
    }
    pub fn as_string(&self) -> String {
        self.internal.to_string()
    }
}

impl From<Address> for payjoin::bitcoin::Address {
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

    pub fn from_string(script: String) -> anyhow::Result<Self, PayjoinError> {
        let buf = BitcoinScriptBuf::from_hex(&script);
        match buf {
            Ok(e) => Ok(Self { internal: e }),
            Err(e) => Err(PayjoinError::InvalidScript { message: e.to_string() }),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.internal.to_bytes()
    }
    pub fn to_hex_string(&self) -> String {
        self.internal.to_hex_string()
    }
    pub fn as_string(&self) -> String {
        self.internal.to_string()
    }
    pub fn to_asm_string(&self) -> String {
        self.internal.to_asm_string()
    }
}

impl From<ScriptBuf> for payjoin::bitcoin::ScriptBuf {
    fn from(value: ScriptBuf) -> Self {
        value.internal
    }
}

impl From<payjoin::bitcoin::ScriptBuf> for ScriptBuf {
    fn from(value: payjoin::bitcoin::ScriptBuf) -> Self {
        ScriptBuf { internal: value }
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    /// The value of the output, in satoshis.
    value: u64,
    /// The address of the output.
    script_pubkey: Arc<ScriptBuf>,
}

impl From<TxOut> for payjoin::bitcoin::TxOut {
    fn from(tx_out: TxOut) -> Self {
        payjoin::bitcoin::TxOut {
            value: tx_out.value,
            script_pubkey: (*tx_out.script_pubkey).clone().internal,
        }
    }
}

impl From<payjoin::bitcoin::TxOut> for TxOut {
    fn from(tx_out: payjoin::bitcoin::TxOut) -> Self {
        TxOut {
            value: tx_out.value,
            script_pubkey: Arc::new(ScriptBuf { internal: tx_out.script_pubkey }),
        }
    }
}

#[derive(Clone, Default)]
pub enum Network {
    ///Bitcoin’s testnet
    Testnet,
    ///Bitcoin’s regtest
    Regtest,
    #[default]
    ///Classic Bitcoin
    Bitcoin,
    ///Bitcoin’s signet
    Signet,
}

impl From<Network> for payjoin::bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Signet => payjoin::bitcoin::Network::Signet,
            Network::Testnet => payjoin::bitcoin::Network::Testnet,
            Network::Regtest => payjoin::bitcoin::Network::Regtest,
            Network::Bitcoin => payjoin::bitcoin::Network::Bitcoin,
        }
    }
}

#[derive(Copy, Clone)]
pub struct FeeRate(payjoin::bitcoin::FeeRate);

impl From<FeeRate> for payjoin::bitcoin::FeeRate {
    fn from(value: FeeRate) -> Self {
        value.0
    }
}

impl From<payjoin::bitcoin::FeeRate> for FeeRate {
    fn from(value: payjoin::bitcoin::FeeRate) -> Self {
        Self(value)
    }
}

impl FeeRate {
    /// 0 sat/kwu.
    pub fn zero() -> Self {
        payjoin::bitcoin::FeeRate::ZERO.into()
    }
    /// Minimum possible value (0 sat/kwu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub fn min() -> Self {
        payjoin::bitcoin::FeeRate::MIN.into()
    }

    /// Maximum possible value.
    pub fn max() -> Self {
        payjoin::bitcoin::FeeRate::MAX.into()
    }

    /// Minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub fn broadcast_min() -> Self {
        payjoin::bitcoin::FeeRate::BROADCAST_MIN.into()
    }

    /// Fee rate used to compute dust amount.
    pub fn dust() -> Self {
        payjoin::bitcoin::FeeRate::DUST.into()
    }

    /// Constructs `FeeRate` from satoshis per 1000 weight units.
    pub fn from_sat_per_kwu(sat_kwu: u64) -> Self {
        payjoin::bitcoin::FeeRate::from_sat_per_kwu(sat_kwu).into()
    }
}
