use std::str::FromStr;

use payjoin::bitcoin;

/// A reference to a transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone)]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: u64,
    /// The address of the output.
    pub script_pubkey: Vec<u8>,
}

impl From<TxOut> for bitcoin::TxOut {
    fn from(tx_out: TxOut) -> Self {
        bitcoin::TxOut {
            value: bitcoin::amount::Amount::from_sat(tx_out.value),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(tx_out.script_pubkey),
        }
    }
}

impl From<bitcoin::TxOut> for TxOut {
    fn from(tx_out: bitcoin::TxOut) -> Self {
        TxOut { value: tx_out.value.to_sat(), script_pubkey: tx_out.script_pubkey.to_bytes() }
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
