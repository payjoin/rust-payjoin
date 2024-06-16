use std::str::FromStr;
use std::sync::Arc;

use crate::error::PayjoinError;
use crate::uri::Url;
///Represents data that needs to be transmitted to the receiver.
///You need to send this request over HTTP(S) to the receiver.
#[derive(Clone, Debug)]
pub struct Request {
    ///URL to send the request to.
    ///
    ///This is full URL with scheme etc - you can pass it right to reqwest or a similar library.
    pub url: Arc<Url>,
    ///Bytes to be sent to the receiver.
    ///
    ///This is properly encoded PSBT, already in base64. You only need to make sure Content-Type is text/plain and Content-Length is body.len() (most libraries do the latter automatically).
    pub body: Vec<u8>,
}

impl From<payjoin::Request> for Request {
    fn from(value: payjoin::Request) -> Self {
        Self { url: Arc::new(value.url.into()), body: value.body }
    }
}

/// A reference to a transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone)]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: u64,
    /// The address of the output.
    pub script_pubkey: Vec<u8>,
}

impl From<TxOut> for payjoin::bitcoin::TxOut {
    fn from(tx_out: TxOut) -> Self {
        payjoin::bitcoin::TxOut {
            value: tx_out.value,
            script_pubkey: payjoin::bitcoin::ScriptBuf::from_bytes(tx_out.script_pubkey),
        }
    }
}

impl From<payjoin::bitcoin::TxOut> for TxOut {
    fn from(tx_out: payjoin::bitcoin::TxOut) -> Self {
        TxOut { value: tx_out.value, script_pubkey: tx_out.script_pubkey.to_bytes() }
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

impl From<payjoin::OhttpKeys> for OhttpKeys {
    fn from(value: payjoin::OhttpKeys) -> Self {
        Self(value)
    }
}
impl From<OhttpKeys> for payjoin::OhttpKeys {
    fn from(value: OhttpKeys) -> Self {
        value.0
    }
}
#[derive(Debug, Clone)]
pub struct OhttpKeys(pub payjoin::OhttpKeys);
impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: Vec<u8>) -> Result<Self, PayjoinError> {
        payjoin::OhttpKeys::decode(bytes.as_slice()).map(|e| e.into()).map_err(|e| e.into())
    }
}
