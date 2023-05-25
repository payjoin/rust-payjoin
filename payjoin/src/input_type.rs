use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::blockdata::script::{Instruction, Instructions, Script};
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::psbt::Input as PsbtInput;

/// Takes the script out of script_sig assuming script_sig signs p2sh script
fn unpack_p2sh(script_sig: &Script) -> Option<&Script> {
    match script_sig.instructions().last()?.ok()? {
        Instruction::PushBytes(bytes) => Some(Script::from_bytes(bytes.as_bytes())),
        Instruction::Op(_) => None,
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum InputType {
    P2Pk,
    P2Pkh,
    P2Sh,
    SegWitV0 { ty: SegWitV0Type, nested: bool },
    Taproot,
}

impl InputType {
    pub(crate) fn from_spent_input(
        txout: &TxOut,
        txin: &PsbtInput,
    ) -> Result<Self, InputTypeError> {
        if txout.script_pubkey.is_p2pk() {
            Ok(InputType::P2Pk)
        } else if txout.script_pubkey.is_p2pkh() {
            Ok(InputType::P2Pkh)
        } else if txout.script_pubkey.is_p2sh() {
            match &txin
                .final_script_sig
                .as_ref()
                .and_then(|script_buf| unpack_p2sh(script_buf.as_ref()))
            {
                Some(script) if script.is_witness_program() =>
                    Self::segwit_from_script(script, true),
                Some(_) => Ok(InputType::P2Sh),
                None => Err(InputTypeError::NotFinalized),
            }
        } else if txout.script_pubkey.is_witness_program() {
            Self::segwit_from_script(&txout.script_pubkey, false)
        } else {
            Err(InputTypeError::UnknownInputType)
        }
    }

    fn segwit_from_script(script: &Script, nested: bool) -> Result<Self, InputTypeError> {
        let mut instructions = script.instructions();
        let witness_version = instructions
            .next()
            .ok_or(InputTypeError::UnknownInputType)?
            .map_err(|_| InputTypeError::UnknownInputType)?;
        match witness_version {
            Instruction::PushBytes(bytes) if bytes.is_empty() =>
                Ok(InputType::SegWitV0 { ty: instructions.try_into()?, nested }),
            Instruction::Op(bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1) => {
                let instruction = instructions
                    .next()
                    .ok_or(InputTypeError::UnknownInputType)?
                    .map_err(|_| InputTypeError::UnknownInputType)?;
                match instruction {
                    Instruction::PushBytes(bytes) if bytes.len() == 32 => Ok(InputType::Taproot),
                    Instruction::PushBytes(_) | Instruction::Op(_) =>
                        Err(InputTypeError::UnknownInputType),
                }
            }
            _ => Err(InputTypeError::UnknownInputType),
        }
    }

    pub(crate) fn expected_input_weight(&self) -> crate::weight::Weight {
        use InputType::*;

        crate::weight::Weight::from_non_witness_data_size(match self {
            P2Pk => unimplemented!(),
            P2Pkh => 148,
            P2Sh => unimplemented!(),
            SegWitV0 { ty: SegWitV0Type::Pubkey, nested: false } => 68,
            SegWitV0 { ty: SegWitV0Type::Pubkey, nested: true } => 91,
            SegWitV0 { ty: SegWitV0Type::Script, nested: _ } => unimplemented!(),
            Taproot => 58,
        })
    }
}

impl fmt::Display for InputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputType::P2Pk => write!(f, "P2PK"),
            InputType::P2Pkh => write!(f, "P2PKH"),
            InputType::P2Sh => write!(f, "P2SH"),
            InputType::SegWitV0 { ty, nested } =>
                write!(f, "SegWitV0: type={}, nested={}", ty, nested),
            InputType::Taproot => write!(f, "Taproot"),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SegWitV0Type {
    Pubkey,
    Script,
}

impl TryFrom<Instructions<'_>> for SegWitV0Type {
    type Error = InputTypeError;

    fn try_from(
        mut instructions: bitcoin::blockdata::script::Instructions<'_>,
    ) -> Result<Self, Self::Error> {
        let push = instructions
            .next()
            .ok_or(InputTypeError::UnknownInputType)?
            .map_err(|_| InputTypeError::UnknownInputType)?;
        if instructions.next().is_some() {
            return Err(InputTypeError::UnknownInputType);
        }
        match push {
            Instruction::PushBytes(bytes) if bytes.len() == 20 => Ok(SegWitV0Type::Pubkey),
            Instruction::PushBytes(bytes) if bytes.len() == 32 => Ok(SegWitV0Type::Script),
            Instruction::PushBytes(_) | Instruction::Op(_) => Err(InputTypeError::UnknownInputType),
        }
    }
}

impl fmt::Display for SegWitV0Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegWitV0Type::Pubkey => write!(f, "pubkey"),
            SegWitV0Type::Script => write!(f, "script"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum InputTypeError {
    UnknownInputType,
    NotFinalized,
}

impl fmt::Display for InputTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputTypeError::UnknownInputType => write!(f, "unknown input type"),
            InputTypeError::NotFinalized => write!(f, "input is not finalized"),
        }
    }
}

impl std::error::Error for InputTypeError {}

#[cfg(test)]
mod tests {
    use bitcoin::psbt::Input as PsbtInput;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::{PublicKey, ScriptBuf};

    use super::*;

    fn wrap_p2sh_script(script: &Script) -> ScriptBuf {
        let bytes: PushBytesBuf = script
            .to_bytes()
            .try_into()
            .expect("script should be valid from ScriptBuf::new_v0_p2wsh");
        bitcoin::blockdata::script::Builder::new().push_slice(bytes.as_ref()).into_script()
    }

    #[test]
    fn test_p2pk() {
        let input_type = InputType::from_spent_input(&TxOut { script_pubkey: ScriptBuf::new_p2pk(&PublicKey::from_slice(b"\x02\x50\x86\x3A\xD6\x4A\x87\xAE\x8A\x2F\xE8\x3C\x1A\xF1\xA8\x40\x3C\xB5\x3F\x53\xE4\x86\xD8\x51\x1D\xAD\x8A\x04\x88\x7E\x5B\x23\x52").unwrap()), value: 42, }, &Default::default()).unwrap();
        assert_eq!(input_type, InputType::P2Pk);
    }

    #[test]
    fn test_p2pkh() {
        let input_type = InputType::from_spent_input(&TxOut { script_pubkey: ScriptBuf::new_p2pkh(&PublicKey::from_slice(b"\x02\x50\x86\x3A\xD6\x4A\x87\xAE\x8A\x2F\xE8\x3C\x1A\xF1\xA8\x40\x3C\xB5\x3F\x53\xE4\x86\xD8\x51\x1D\xAD\x8A\x04\x88\x7E\x5B\x23\x52").unwrap().pubkey_hash()), value: 42, }, &Default::default()).unwrap();
        assert_eq!(input_type, InputType::P2Pkh);
    }

    #[test]
    fn test_p2sh() {
        let script = ScriptBuf::new_op_return(&[42]);
        let input_type = InputType::from_spent_input(
            &TxOut { script_pubkey: ScriptBuf::new_p2sh(&script.script_hash()), value: 42 },
            &PsbtInput { final_script_sig: Some(script), ..Default::default() },
        )
        .unwrap();
        assert_eq!(input_type, InputType::P2Sh);
    }

    #[test]
    fn test_p2wpkh() {
        let input_type = InputType::from_spent_input(&TxOut { script_pubkey: ScriptBuf::new_v0_p2wpkh(&PublicKey::from_slice(b"\x02\x50\x86\x3A\xD6\x4A\x87\xAE\x8A\x2F\xE8\x3C\x1A\xF1\xA8\x40\x3C\xB5\x3F\x53\xE4\x86\xD8\x51\x1D\xAD\x8A\x04\x88\x7E\x5B\x23\x52").unwrap().wpubkey_hash().expect("WTF, the key is uncompressed")), value: 42, }, &Default::default()).unwrap();
        assert_eq!(input_type, InputType::SegWitV0 { ty: SegWitV0Type::Pubkey, nested: false });
    }

    #[test]
    fn test_p2wsh() {
        let script = ScriptBuf::new_op_return(&[42]);
        let input_type = InputType::from_spent_input(
            &TxOut { script_pubkey: ScriptBuf::new_v0_p2wsh(&script.wscript_hash()), value: 42 },
            &PsbtInput { final_script_sig: Some(script), ..Default::default() },
        )
        .unwrap();
        assert_eq!(input_type, InputType::SegWitV0 { ty: SegWitV0Type::Script, nested: false });
    }

    #[test]
    fn test_p2sh_p2wpkh() {
        let segwit_script = ScriptBuf::new_v0_p2wpkh(&PublicKey::from_slice(b"\x02\x50\x86\x3A\xD6\x4A\x87\xAE\x8A\x2F\xE8\x3C\x1A\xF1\xA8\x40\x3C\xB5\x3F\x53\xE4\x86\xD8\x51\x1D\xAD\x8A\x04\x88\x7E\x5B\x23\x52").unwrap().wpubkey_hash().expect("WTF, the key is uncompressed"));
        let segwit_script_hash = segwit_script.script_hash();
        let script_sig = wrap_p2sh_script(&segwit_script);

        let input_type = InputType::from_spent_input(
            &TxOut { script_pubkey: ScriptBuf::new_p2sh(&segwit_script_hash), value: 42 },
            &PsbtInput { final_script_sig: Some(script_sig), ..Default::default() },
        )
        .unwrap();
        assert_eq!(input_type, InputType::SegWitV0 { ty: SegWitV0Type::Pubkey, nested: true });
    }

    #[test]
    fn test_p2sh_p2wsh() {
        let script = ScriptBuf::new_op_return(&[42]);
        let segwit_script = ScriptBuf::new_v0_p2wsh(&script.wscript_hash());
        let segwit_script_hash = segwit_script.script_hash();
        let script_sig = wrap_p2sh_script(&segwit_script);

        let input_type = InputType::from_spent_input(
            &TxOut { script_pubkey: ScriptBuf::new_p2sh(&segwit_script_hash), value: 42 },
            &PsbtInput { final_script_sig: Some(script_sig), ..Default::default() },
        )
        .unwrap();
        assert_eq!(input_type, InputType::SegWitV0 { ty: SegWitV0Type::Script, nested: true });
    }

    // TODO: test p2tr
}
