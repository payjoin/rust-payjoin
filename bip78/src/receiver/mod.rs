use bitcoin::{util::psbt::PartiallySignedTransaction as Psbt, AddressType, Script, TxOut};

mod error;

use error::InternalRequestError;
pub use error::RequestError;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub struct UncheckedProposal {
    psbt: Psbt,
}

pub struct MaybeInputsOwned {
    psbt: Psbt,
}

pub struct MaybeMixedInputScripts {
    psbt: Psbt,
}

pub struct MaybeInputsSeen {
    psbt: Psbt,
}

impl UncheckedProposal {
    pub fn from_request(
        body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, RequestError> {
        use crate::bitcoin::consensus::Decodable;

        let content_type = headers.get_header("content-type").ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if !content_type.starts_with("text/plain") {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut limited = body.take(content_length);
        let reader = base64::read::DecoderReader::new(&mut limited, base64::STANDARD);
        let psbt = Psbt::consensus_decode(reader).map_err(InternalRequestError::Decode)?;

        Ok(UncheckedProposal {
            psbt,
        })
    }

    /// The Sender's Original PSBT
    pub fn get_transaction_to_check_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    /// 
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `get_transaction_to_check_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive PayJoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn assume_tested_and_scheduled_broadcast(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt }
    }

    /// Call this method if the only way to initiate a PayJoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receive_endpoint(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt }
    }
}

impl MaybeInputsOwned {
    /// The receiver should not be able to sign for any of these Original PSBT inputs.
    /// 
    /// Check that none of them are owned by the receiver downstream before proceeding.
    pub fn iter_input_script_pubkeys(&self) -> Vec<Result<&Script, RequestError>> {
        todo!() // return impl '_ + Iterator<Item = Result<&Script, RequestError>>
    }

    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    /// Call this after checking downstream.
    pub fn assume_inputs_not_owned(self) -> MaybeMixedInputScripts {
        MaybeMixedInputScripts { psbt: self.psbt }
    }
}

impl MaybeMixedInputScripts {
    /// If there is only 1 input type, the receiver should be able to produce the same
    /// type.
    ///
    /// Check downstream before proceeding.
    pub fn iter_input_script_types(&self) -> Vec<Result<&AddressType, RequestError>> {
        todo!() // return Iterator<Item = Result<&AddressType, RequestError>>
    }

    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn assume_no_mixed_input_scripts(self) -> MaybeInputsSeen {
        MaybeInputsSeen { psbt: self.psbt }
    }
}

impl MaybeInputsSeen {
    /// The receiver should not have sent to or received the Original PSBT's inputs before.
    ///
    /// Check that these are unknown, never before seen inputs before proceeding.
    pub fn iter_input_outpoints(&self) -> impl '_ + Iterator<Item=&bitcoin::OutPoint> {
        self.psbt.global.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant PayJoin, where a sender
    /// proposes a PayJoin PSBT as a new Original PSBT for a new PayJoin.
    ///
    /// Call this after checking downstream.
    pub fn assume_no_inputs_seen_before(self) -> UnlockedProposal {
        UnlockedProposal { psbt: self.psbt }
    }
}

pub struct UnlockedProposal {
    psbt: Psbt,
}

impl UnlockedProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item=&bitcoin::OutPoint> {
        self.psbt.global.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn assume_locked(self) -> Proposal {
        Proposal {
            psbt: self.psbt,
        }
    }
}

/// Transaction that must be broadcasted.
#[must_use = "The transaction must be broadcasted to prevent abuse"]
pub struct MustBroadcast(pub bitcoin::Transaction);

pub struct Proposal {
    psbt: Psbt,
}

/*
impl Proposal {
    pub fn replace_output_script(&mut self, new_output_script: Script, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn replace_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn insert_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn expected_missing_fee_for_replaced_output(&self, output_type: OutputType) -> bitcoin::Amount {
    }
}
*/

pub struct ReceiverOptions {
    dust_limit: bitcoin::Amount,
}

pub enum BumpFeePolicy {
    FailOnInsufficient,
    SubtractOurFeeOutput,
}

pub struct NewOutputOptions {
    set_as_fee_output: bool,
    subtract_fees_from_this: bool,
}
