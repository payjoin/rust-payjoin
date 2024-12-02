use std::str::FromStr;
use std::sync::Arc;

use payjoin::bitcoin;

/// A reference to a transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PsbtInput {
    pub witness_utxo: Option<TxOut>,
    pub redeem_script: Option<Arc<Script>>,
    pub witness_script: Option<Arc<Script>>,
}

impl PsbtInput {
    pub fn new(
        witness_utxo: Option<TxOut>,
        redeem_script: Option<Arc<Script>>,
        witness_script: Option<Arc<Script>>,
    ) -> Self {
        Self { witness_utxo, redeem_script, witness_script }
    }
}

impl From<bitcoin::psbt::Input> for PsbtInput {
    fn from(psbt_input: bitcoin::psbt::Input) -> Self {
        Self {
            witness_utxo: psbt_input.witness_utxo.map(|s| s.into()),
            redeem_script: psbt_input.redeem_script.clone().map(|s| Arc::new(s.into())),
            witness_script: psbt_input.witness_script.clone().map(|s| Arc::new(s.into())),
        }
    }
}

impl From<PsbtInput> for bitcoin::psbt::Input {
    fn from(psbt_input: PsbtInput) -> Self {
        Self {
            witness_utxo: psbt_input.witness_utxo.map(|s| s.into()),
            redeem_script: psbt_input.redeem_script.map(|s| Arc::unwrap_or_clone(s).into()),
            witness_script: psbt_input.witness_script.map(|s| Arc::unwrap_or_clone(s).into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TxIn {
    pub previous_output: OutPoint,
}

impl From<TxIn> for bitcoin::TxIn {
    fn from(tx_in: TxIn) -> Self {
        bitcoin::TxIn { previous_output: tx_in.previous_output.into(), ..Default::default() }
    }
}

impl From<bitcoin::TxIn> for TxIn {
    fn from(tx_in: bitcoin::TxIn) -> Self {
        TxIn { previous_output: tx_in.previous_output.into() }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Script(pub payjoin::bitcoin::ScriptBuf);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Script {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(script: Vec<u8>) -> Self {
        Self(payjoin::bitcoin::ScriptBuf::from_bytes(script))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl From<payjoin::bitcoin::ScriptBuf> for Script {
    fn from(value: payjoin::bitcoin::ScriptBuf) -> Self {
        Self(value)
    }
}

impl From<Script> for payjoin::bitcoin::ScriptBuf {
    fn from(value: Script) -> Self {
        value.0
    }
}
