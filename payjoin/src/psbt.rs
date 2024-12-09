//! Utilities to make work with PSBTs easier

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::address::FromScriptError;
use bitcoin::blockdata::script::Instruction;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::InputWeightPrediction;
use bitcoin::{bip32, psbt, Address, AddressType, Network, OutPoint, Script, TxIn, TxOut, Weight};

#[derive(Debug)]
pub(crate) enum InconsistentPsbt {
    UnequalInputCounts { tx_ins: usize, psbt_ins: usize },
    UnequalOutputCounts { tx_outs: usize, psbt_outs: usize },
}

impl fmt::Display for InconsistentPsbt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins, } => write!(f, "The number of PSBT inputs ({}) doesn't equal to the number of unsigned transaction inputs ({})", psbt_ins, tx_ins),
            InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs, } => write!(f, "The number of PSBT outputs ({}) doesn't equal to the number of unsigned transaction outputs ({})", psbt_outs, tx_outs),
        }
    }
}

impl std::error::Error for InconsistentPsbt {}

/// Error type for merging two unique unsigned PSBTs
#[derive(Debug, PartialEq)]
pub(crate) enum MergePsbtError {
    /// Input from other PSBT already exists in this PSBT
    InputAlreadyExists(OutPoint),
    /// Input is already signed
    MyInputIsSigned(OutPoint),
    /// Other PSBT's input is already signed
    OtherInputIsSigned(OutPoint),
}

impl fmt::Display for MergePsbtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InputAlreadyExists(outpoint) =>
                write!(f, "input already exists with outpoint: {}", outpoint),
            Self::MyInputIsSigned(outpoint) =>
                write!(f, "my input is already signed with outpoint: {}", outpoint),
            Self::OtherInputIsSigned(outpoint) =>
                write!(f, "other input is already signed with outpoint: {}", outpoint),
        }
    }
}

impl std::error::Error for MergePsbtError {}
/// Our Psbt type for validation and utilities
pub(crate) trait PsbtExt: Sized {
    fn inputs_mut(&mut self) -> &mut [psbt::Input];
    fn outputs_mut(&mut self) -> &mut [psbt::Output];
    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)>;
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_>;
    // guarantees that length of psbt input matches that of unsigned_tx inputs and same
    /// thing for outputs.
    fn validate(self) -> Result<Self, InconsistentPsbt>;
    fn validate_input_utxos(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError>;
    fn dangerous_clear_signatures(&mut self);
    fn merge_unsigned_tx(&mut self, other: Self) -> Result<(), Vec<MergePsbtError>>;
}

impl PsbtExt for Psbt {
    fn inputs_mut(&mut self) -> &mut [psbt::Input] { &mut self.inputs }

    fn outputs_mut(&mut self) -> &mut [psbt::Output] { &mut self.outputs }

    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)> {
        &mut self.xpub
    }

    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }

    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_> {
        Box::new(
            self.unsigned_tx
                .input
                .iter()
                .zip(&self.inputs)
                .map(|(txin, psbtin)| InternalInputPair { txin, psbtin }),
        )
    }

    fn validate(self) -> Result<Self, InconsistentPsbt> {
        let tx_ins = self.unsigned_tx.input.len();
        let psbt_ins = self.inputs.len();
        let tx_outs = self.unsigned_tx.output.len();
        let psbt_outs = self.outputs.len();

        if psbt_ins != tx_ins {
            Err(InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins })
        } else if psbt_outs != tx_outs {
            Err(InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs })
        } else {
            Ok(self)
        }
    }

    fn validate_input_utxos(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError> {
        self.input_pairs().enumerate().try_for_each(|(index, input)| {
            input
                .validate_utxo(treat_missing_as_error)
                .map_err(|error| PsbtInputsError { index, error })
        })
    }

    /// Clear all script sig and witness fields from this PSBT
    fn dangerous_clear_signatures(&mut self) {
        for input in self.inputs.iter_mut() {
            input.final_script_sig = None;
            input.final_script_witness = None;
        }
    }

    /// Try to merge two PSBTs
    /// PSBTs here are assumed to not have the same unsigned tx
    /// if you do have the same unsigned tx, use `combine` instead
    /// Note this method does not merge non inputs or outputs
    fn merge_unsigned_tx(&mut self, other: Self) -> Result<(), Vec<MergePsbtError>> {
        let mut errors = Vec::new();
        for (input, txin) in self.inputs.iter().zip(self.unsigned_tx.input.iter()) {
            if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
                errors.push(MergePsbtError::MyInputIsSigned(txin.previous_output));
            }
        }

        // Do the same for the other PSBT down below
        let mut inputs_to_add = Vec::with_capacity(other.inputs.len());
        let mut txins_to_add = Vec::with_capacity(other.inputs.len());
        for (other_input, other_txin) in other.inputs.iter().zip(other.unsigned_tx.input.iter()) {
            if self.unsigned_tx.input.contains(&other_txin) {
                errors.push(MergePsbtError::InputAlreadyExists(other_txin.previous_output));
            }

            if other_input.final_script_sig.is_some() || other_input.final_script_witness.is_some()
            {
                errors.push(MergePsbtError::OtherInputIsSigned(other_txin.previous_output));
                continue;
            }

            inputs_to_add.push(other_input.clone());
            txins_to_add.push(other_txin.clone());
        }

        let mut outputs_to_add = Vec::with_capacity(other.outputs.len());
        let mut txouts_to_add = Vec::with_capacity(other.outputs.len());
        for (other_output, other_txout) in other.outputs.iter().zip(other.unsigned_tx.output.iter())
        {
            // TODO(armins) if we recognize the exact same output this is a not neccecarily an error but an indication for an improved tx structure
            outputs_to_add.push(other_output.clone());
            txouts_to_add.push(other_txout.clone());
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        self.inputs.extend(inputs_to_add);
        self.unsigned_tx.input.extend(txins_to_add);
        self.outputs.extend(outputs_to_add);
        self.unsigned_tx.output.extend(txouts_to_add);

        Ok(())
    }
}

/// Gets redeemScript from the script_sig following BIP16 rules regarding P2SH spending.
fn redeem_script(script_sig: &Script) -> Option<&Script> {
    match script_sig.instructions().last()?.ok()? {
        Instruction::PushBytes(bytes) => Some(Script::from_bytes(bytes.as_bytes())),
        Instruction::Op(_) => None,
    }
}

// input script: 0x160014{20-byte-key-hash} = 23 bytes
// witness: <signature> <pubkey> = 72, 33 bytes
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh-nested-in-bip16-p2sh
const NESTED_P2WPKH_MAX: InputWeightPrediction = InputWeightPrediction::from_slice(23, &[72, 33]);

#[derive(Clone, Debug)]
pub(crate) struct InternalInputPair<'a> {
    pub txin: &'a TxIn,
    pub psbtin: &'a psbt::Input,
}

impl InternalInputPair<'_> {
    /// Returns TxOut associated with the input
    pub fn previous_txout(&self) -> Result<&TxOut, PrevTxOutError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) => Err(PrevTxOutError::MissingUtxoInformation),
            (_, Some(txout)) => Ok(txout),
            (Some(tx), None) => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or(PrevTxOutError::IndexOutOfBounds {
                    output_count: tx.output.len(),
                    index: self.txin.previous_output.vout,
                }),
        }
    }

    pub fn validate_utxo(
        &self,
        treat_missing_as_error: bool,
    ) -> Result<(), InternalPsbtInputError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) if treat_missing_as_error =>
                Err(InternalPsbtInputError::PrevTxOut(PrevTxOutError::MissingUtxoInformation)),
            (None, None) => Ok(()),
            (Some(tx), None) if tx.compute_txid() == self.txin.previous_output.txid => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or_else(|| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                    .into()
                })
                .map(drop),
            (Some(_), None) => Err(InternalPsbtInputError::UnequalTxid),
            (None, Some(_)) => Ok(()),
            (Some(tx), Some(witness_txout))
                if tx.compute_txid() == self.txin.previous_output.txid =>
            {
                let non_witness_txout = tx
                    .output
                    .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                        PrevTxOutError::IndexOutOfBounds {
                            output_count: tx.output.len(),
                            index: self.txin.previous_output.vout,
                        }
                    })?)
                    .ok_or(PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    })?;
                if witness_txout == non_witness_txout {
                    Ok(())
                } else {
                    Err(InternalPsbtInputError::SegWitTxOutMismatch)
                }
            }
            (Some(_), Some(_)) => Err(InternalPsbtInputError::UnequalTxid),
        }
    }

    pub fn address_type(&self) -> Result<AddressType, AddressTypeError> {
        let txo = self.previous_txout()?;
        // HACK: Network doesn't matter for our use case of only getting the address type
        // but is required in the `from_script` interface. Hardcoded to mainnet.
        Address::from_script(&txo.script_pubkey, Network::Bitcoin)?
            .address_type()
            .ok_or(AddressTypeError::UnknownAddressType)
    }

    pub fn expected_input_weight(&self) -> Result<Weight, InputWeightError> {
        use bitcoin::AddressType::*;

        // Get the input weight prediction corresponding to spending an output of this address type
        let iwp = match self.address_type()? {
            P2pkh => Ok(InputWeightPrediction::P2PKH_COMPRESSED_MAX),
            P2sh => {
                // redeemScript can be extracted from scriptSig for signed P2SH inputs
                let redeem_script = if let Some(ref script_sig) = self.psbtin.final_script_sig {
                    redeem_script(script_sig)
                // try the PSBT redeem_script field for unsigned inputs.
                } else {
                    self.psbtin.redeem_script.as_ref().map(|script| script.as_ref())
                };
                match redeem_script {
                    // Nested segwit p2wpkh.
                    Some(script) if script.is_witness_program() && script.is_p2wpkh() =>
                        Ok(NESTED_P2WPKH_MAX),
                    // Other script or witness program.
                    Some(_) => Err(InputWeightError::NotSupported),
                    // No redeem script provided. Cannot determine the script type.
                    None => Err(InputWeightError::NoRedeemScript),
                }
            }
            P2wpkh => Ok(InputWeightPrediction::P2WPKH_MAX),
            P2wsh => Err(InputWeightError::NotSupported),
            P2tr => Ok(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH),
            _ => Err(AddressTypeError::UnknownAddressType.into()),
        }?;

        // Lengths of txid, index and sequence: (32, 4, 4).
        let input_weight = iwp.weight() + Weight::from_non_witness_data_size(32 + 4 + 4);
        Ok(input_weight)
    }
}

#[derive(Debug)]
pub(crate) enum PrevTxOutError {
    MissingUtxoInformation,
    IndexOutOfBounds { output_count: usize, index: u32 },
}

impl fmt::Display for PrevTxOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrevTxOutError::MissingUtxoInformation => write!(f, "missing UTXO information"),
            PrevTxOutError::IndexOutOfBounds { output_count, index } => {
                write!(f, "index {} out of bounds (number of outputs: {})", index, output_count)
            }
        }
    }
}

impl std::error::Error for PrevTxOutError {}

#[derive(Debug)]
pub(crate) enum InternalPsbtInputError {
    PrevTxOut(PrevTxOutError),
    UnequalTxid,
    /// TxOut provided in `segwit_utxo` doesn't match the one in `non_segwit_utxo`
    SegWitTxOutMismatch,
    AddressType(AddressTypeError),
    NoRedeemScript,
}

impl fmt::Display for InternalPsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::UnequalTxid => write!(f, "transaction ID of previous transaction doesn't match one specified in input spending it"),
            Self::SegWitTxOutMismatch => write!(f, "transaction output provided in SegWit UTXO field doesn't match the one in non-SegWit UTXO field"),
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::NoRedeemScript => write!(f, "provided p2sh PSBT input is missing a redeem_script"),
        }
    }
}

impl std::error::Error for InternalPsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::UnequalTxid => None,
            Self::SegWitTxOutMismatch => None,
            Self::AddressType(error) => Some(error),
            Self::NoRedeemScript => None,
        }
    }
}

impl From<PrevTxOutError> for InternalPsbtInputError {
    fn from(value: PrevTxOutError) -> Self { InternalPsbtInputError::PrevTxOut(value) }
}

impl From<AddressTypeError> for InternalPsbtInputError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

#[derive(Debug)]
pub struct PsbtInputError(InternalPsbtInputError);

impl From<InternalPsbtInputError> for PsbtInputError {
    fn from(e: InternalPsbtInputError) -> Self { PsbtInputError(e) }
}

impl fmt::Display for PsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for PsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[derive(Debug)]
pub struct PsbtInputsError {
    index: usize,
    error: InternalPsbtInputError,
}

impl fmt::Display for PsbtInputsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PSBT input #{}", self.index)
    }
}

impl std::error::Error for PsbtInputsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}

#[derive(Debug)]
pub(crate) enum AddressTypeError {
    PrevTxOut(PrevTxOutError),
    InvalidScript(FromScriptError),
    UnknownAddressType,
}

impl fmt::Display for AddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::InvalidScript(_) => write!(f, "invalid script"),
            Self::UnknownAddressType => write!(f, "unknown address type"),
        }
    }
}

impl std::error::Error for AddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::InvalidScript(error) => Some(error),
            Self::UnknownAddressType => None,
        }
    }
}

impl From<PrevTxOutError> for AddressTypeError {
    fn from(value: PrevTxOutError) -> Self { Self::PrevTxOut(value) }
}

impl From<FromScriptError> for AddressTypeError {
    fn from(value: FromScriptError) -> Self { Self::InvalidScript(value) }
}

#[derive(Debug)]
pub(crate) enum InputWeightError {
    AddressType(AddressTypeError),
    NoRedeemScript,
    NotSupported,
}

impl fmt::Display for InputWeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::NoRedeemScript => write!(f, "p2sh input missing a redeem script"),
            Self::NotSupported => write!(f, "weight prediction not supported"),
        }
    }
}

impl std::error::Error for InputWeightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddressType(error) => Some(error),
            Self::NoRedeemScript => None,
            Self::NotSupported => None,
        }
    }
}
impl From<AddressTypeError> for InputWeightError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

// Tests
#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::rand::thread_rng;
    use bitcoin::secp256k1::SECP256K1;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, Txid, Witness};
    use hpke::rand_core::RngCore;

    use super::*;

    const NETWORK: Network = Network::Regtest;

    /// Util function to create a random p2wpkh script
    pub fn random_p2wpkh_script() -> ScriptBuf {
        let sk = bitcoin::PrivateKey::generate(NETWORK);
        let pk = sk.public_key(SECP256K1);

        pk.p2wpkh_script_code().unwrap()
    }

    /// Util function to create a random txid
    pub fn random_txid() -> Txid {
        let mut rng = thread_rng();
        let mut txid = [0u8; 32];
        rng.try_fill_bytes(&mut txid).unwrap();
        Txid::from_slice(&txid).unwrap()
    }

    // Util function to create a btc tx with random inputs and outputs as defined by fn params
    fn create_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
        let txid = random_txid();

        let mut inputs = vec![];
        for i in 0..num_inputs {
            let op = OutPoint::new(txid, i as u32);
            inputs.push(TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            });
        }

        let mut outputs = vec![];
        for _ in 0..num_outputs {
            outputs.push(TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: random_p2wpkh_script(),
            });
        }

        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    #[test]
    pub fn test_clear_signatures() {
        let mut psbt = Psbt::from_unsigned_tx(create_tx(1, 1)).unwrap();
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
        psbt.inputs[0].final_script_witness = Some(Witness::new());

        psbt.dangerous_clear_signatures();
        assert_eq!(psbt.inputs[0].final_script_sig, None);
        assert_eq!(psbt.inputs[0].final_script_witness, None);
    }
    #[test]
    fn test_merge_unsigned_tx() {
        let tx_1 = create_tx(1, 1);
        let tx_2 = create_tx(1, 1);
        let original_psbt = Psbt::from_unsigned_tx(tx_1).unwrap();
        let mut merged_psbt = original_psbt.clone();
        let other = Psbt::from_unsigned_tx(tx_2).unwrap();
        merged_psbt.merge_unsigned_tx(other.clone()).expect("should merge two unique psbts");

        assert_eq!(merged_psbt.inputs[0], original_psbt.inputs[0]);
        assert_eq!(merged_psbt.inputs[1], other.inputs[0]);
        assert_eq!(merged_psbt.outputs[0], original_psbt.outputs[0]);
        assert_eq!(merged_psbt.outputs[1], other.outputs[0]);

        // Assert unsigned tx is also updated
        let merged_tx = merged_psbt.unsigned_tx.clone();
        assert_eq!(merged_tx.input[0], original_psbt.unsigned_tx.input[0]);
        assert_eq!(merged_tx.input[1], other.unsigned_tx.input[0]);
        assert_eq!(merged_tx.output[0], original_psbt.unsigned_tx.output[0]);
        assert_eq!(merged_tx.output[1], other.unsigned_tx.output[0]);
    }

    #[test]
    fn should_not_merge_if_psbt_share_inputs() {
        let tx_1 = create_tx(1, 1);
        let original_psbt = Psbt::from_unsigned_tx(tx_1.clone()).unwrap();
        let mut merged_psbt = original_psbt.clone();
        let other = original_psbt.clone();

        let res = merged_psbt.merge_unsigned_tx(other.clone());
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap()[0],
            MergePsbtError::InputAlreadyExists(tx_1.input[0].previous_output)
        );
        // ensure the psbt has not been modified
        assert_eq!(merged_psbt, original_psbt);
    }

    #[test]
    fn should_not_merge_signed_psbt() {
        let tx_1 = create_tx(1, 1);
        let tx_2 = create_tx(1, 1);
        let mut original_psbt = Psbt::from_unsigned_tx(tx_1.clone()).unwrap();
        let mut other = Psbt::from_unsigned_tx(tx_2.clone()).unwrap();
        
        // Lets add some witness data
        original_psbt.inputs[0].final_script_witness = Some(Witness::new());
        other.inputs[0].final_script_witness = Some(Witness::new());
        let mut merged_psbt = original_psbt.clone();
        let res = merged_psbt.merge_unsigned_tx(other.clone());
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap()[0],
            MergePsbtError::MyInputIsSigned(tx_1.input[0].previous_output)
        );
        // ensure the psbt has not been modified
        assert_eq!(merged_psbt, original_psbt);
        // Lets try the same thing with the second psbt
        let err = merged_psbt.merge_unsigned_tx(other.clone()).err().unwrap();
        assert!(err.contains(&MergePsbtError::OtherInputIsSigned(tx_2.input[0].previous_output)));
        assert!(err.contains(&MergePsbtError::MyInputIsSigned(tx_1.input[0].previous_output)));
        // ensure the psbt has not been modified
        assert_eq!(merged_psbt, original_psbt);
    }
}
