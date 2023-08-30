pub mod bitcoind;
pub mod error;
pub mod receive;
pub mod send;
#[cfg(test)]
mod test;
pub mod transaction;
pub mod uri;
pub use payjoin::bitcoin;
use payjoin::bitcoin::{
    address::{ NetworkChecked, NetworkUnchecked },
    Address as _BitcoinAdrress,
    ScriptBuf as BitcoinScriptBuf,
};
pub use payjoin::Error as PdkError;
use serde::{ Deserialize, Serialize };
use std::{ collections::HashSet, fs::OpenOptions, str::FromStr };
uniffi::include_scaffolding!("pdk");
pub struct CachedOutputs {
    pub outputs: HashSet<OutPoint>,
    pub file: std::fs::File,
}
impl CachedOutputs {
    pub fn new(path: String) -> Result<Self, bitcoincore_rpc::Error> {
        let mut file = OpenOptions::new().write(true).read(true).create(true).open(path)?;
        let outputs = bitcoincore_rpc::jsonrpc::serde_json
            ::from_reader(&mut file)
            .unwrap_or_else(|_| HashSet::new());
        Ok(Self { outputs, file })
    }
}

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

//TODO; RECREATE ADDRESS STRUCTURE
#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    pub internal: BitcoinAddress,
}
#[derive(Debug, Clone, PartialEq)]
pub enum BitcoinAddress {
    Unchecked(_BitcoinAdrress<NetworkUnchecked>),
    Checked(_BitcoinAdrress<NetworkChecked>),
}

impl Address {
    pub fn from_script(script: ScriptBuf, network: Network) -> Result<Self, anyhow::Error> {
        match _BitcoinAdrress::from_script(script.inner.as_script(), network.into()) {
            Ok(e) => Ok(Address { internal: BitcoinAddress::Checked(e) }),
            Err(e) => anyhow::bail!(e),
        }
    }
    pub fn assume_checked(self) -> Result<Self, anyhow::Error> {
        match self.internal {
            BitcoinAddress::Unchecked(e) => {
                Ok(Address { internal: BitcoinAddress::Checked(e.assume_checked()) })
            }
            BitcoinAddress::Checked(e) => Ok(Address { internal: BitcoinAddress::Checked(e) }),
        }
    }
    pub fn from_str(address: &str) -> Result<Self, anyhow::Error> {
        match _BitcoinAdrress::from_str(&address) {
            Ok(e) => Ok(Address { internal: BitcoinAddress::Unchecked(e) }),
            Err(e) => anyhow::bail!(e),
        }
    }
    pub fn to_string(self) -> String {
        match self.internal {
            BitcoinAddress::Unchecked(e) => serde_json::to_string(&e).unwrap(),
            BitcoinAddress::Checked(e) => serde_json::to_string(&e).unwrap(),
        }
    }
}

impl From<Address> for bitcoin::Address {
    fn from(value: Address) -> Self {
        match value.internal {
            BitcoinAddress::Unchecked(e) => e.assume_checked(),
            BitcoinAddress::Checked(e) => e,
        }
    }
}
#[derive(Debug, Clone)]
pub struct ScriptBuf {
    inner: BitcoinScriptBuf,
}
impl ScriptBuf {
    pub fn new(raw_output_script: Vec<u8>) -> Self {
        let buf = BitcoinScriptBuf::from_bytes(raw_output_script);
        ScriptBuf { inner: buf }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.get_internal().to_bytes()
    }
    pub fn to_hex_string(self) -> String {
        self.get_internal().to_hex_string()
    }
    pub fn to_string(self) -> String {
        self.get_internal().to_string()
    }
    pub fn to_asm_string(self) -> String {
        self.get_internal().to_asm_string()
    }
    fn get_internal(self) -> BitcoinScriptBuf {
        self.inner
    }
}
impl From<ScriptBuf> for bitcoin::ScriptBuf {
    fn from(value: ScriptBuf) -> Self {
        value.get_internal()
    }
}
impl From<bitcoin::ScriptBuf> for ScriptBuf {
    fn from(value: bitcoin::ScriptBuf) -> Self {
        ScriptBuf { inner: value }
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
        bitcoin::TxOut { value: tx_out.value, script_pubkey: tx_out.script_pubkey.get_internal() }
    }
}

impl From<bitcoin::TxOut> for TxOut {
    fn from(tx_out: bitcoin::TxOut) -> Self {
        TxOut {
            value: tx_out.value,
            script_pubkey: ScriptBuf { inner: tx_out.script_pubkey.into() },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum AddressType {
    Legacy,
    P2shSegwit,
    Bech32,
    Bech32m,
}
impl From<AddressType> for bitcoincore_rpc::json::AddressType {
    fn from(value: AddressType) -> Self {
        return match value {
            AddressType::Legacy => bitcoincore_rpc::json::AddressType::Legacy,
            AddressType::P2shSegwit => bitcoincore_rpc::json::AddressType::P2shSegwit,
            AddressType::Bech32 => bitcoincore_rpc::json::AddressType::Bech32,
            AddressType::Bech32m => bitcoincore_rpc::json::AddressType::Bech32m,
        };
    }
}
pub struct Input {
    pub txid: String,
    pub vout: u32,
    pub sequence: Option<u32>,
}
impl Input {
    pub fn new(txid: String, vout: u32, sequence: Option<u32>) -> Self {
        Self { txid, vout, sequence }
    }
}
impl From<&Input> for bitcoincore_rpc::json::CreateRawTransactionInput {
    fn from(value: &Input) -> Self {
        bitcoincore_rpc::json::CreateRawTransactionInput {
            txid: bitcoin::Txid::from_str(&value.txid).expect("Invalid Txid"),
            vout: value.vout,
            sequence: value.sequence,
        }
    }
}
#[derive(Clone)]
///The cryptocurrency to act on
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
