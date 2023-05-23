//! Receive Payjoin
//!
//! This module contains types and methods used to receive payjoin via BIP78.
//! Usage is pretty simple:
//!
//! 1. Generate a pj_uri [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) using [`payjoin::Uri`](crate::Uri)::from_str
//! 2. Listen for a sender's request on the `pj` endpoint
//! 3. Parse the request using [`UncheckedProposal::from_request()`](crate::receive::UncheckedProposal::from_request())
//! 4. Validate the proposal using the `check` methods to guide you.
//! 5. Assuming the proposal is valid, augment it into a payjoin with the available `try_preserving_privacy` and `contribute` methods
//! 6. Extract the payjoin PSBT and sign it
//! 7. Respond to the sender's http request with the signed PSBT as payload.
//!
//! ## Receive a Payjoin
//!
//! The `receive` feature provides all of the check methods, PSBT data manipulation, coin selection, and transport structures to receive payjoin and handle errors in a privacy preserving way.
//!
//! Receiving payjoin entails listening to a secure http endpoint for inbound requests. The endpoint is displayed in the `pj` parameter of a [bip 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) request URI.
//!
//! The [reference implementation annotated below](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) uses `rouille` sync http server and Bitcoin Core RPC.
//!
//! ```
//! fn receive_payjoin(
//!     bitcoind: bitcoincore_rpc::Client,
//!     amount_arg: &str,
//!     endpoint_arg: &str,
//! ) -> Result<()>
//! ```
//!
//! ### 1. Generate a pj_uri BIP21 using `payjoin::Uri::from_str`
//!
//! A BIP 21 URI supporting payjoin contains at minimum a bitcoin address and a secure `pj` endpoint.
//!
//! ```
//! let pj_receiver_address = bitcoind.get_new_address(None, None)?;
//! let amount = Amount::from_sat(amount_arg.parse()?);
//! let pj_uri_string = format!(
//!     "{}?amount={}&pj={}",
//!     pj_receiver_address.to_qr_uri(),
//!     amount.to_btc(),
//!     endpoint_arg
//! );
//! let pj_uri = Uri::from_str(&pj_uri_string)
//!     .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?;
//! let _pj_uri = pj_uri
//!     .check_pj_supported()
//!     .map_err(|e| anyhow!("Constructed URI does not support payjoin: {}", e))?;
//! ```
//!
//! ### 2. Listen for a sender's request on the `pj` endpoint
//!
//! Start a webserver of your choice to respond to payjoin protocol POST messages. The reference `payjoin-cli` implementation uses `rouille` sync http server.
//!
//! ```
//! rouille::start_server(self.config.pj_host.clone(), move |req| self.handle_web_request(req));
//! // ...
//! fn handle_web_request(&self, req: &Request) -> Response {
//!     log::debug!("Received request: {:?}", req);
//!     match (req.method(), req.url().as_ref()) {
//!         // ...
//!         ("POST", _) => self
//!             .handle_payjoin_post(req)
//!             .map_err(|e| match e {
//!                 Error::BadRequest(e) => {
//!                     log::error!("Error handling request: {}", e);
//!                     Response::text(e.to_string()).with_status_code(400)
//!                 }
//!                 e => {
//!                     log::error!("Error handling request: {}", e);
//!                     Response::text(e.to_string()).with_status_code(500)
//!                 }
//!             })
//!             .unwrap_or_else(|err_resp| err_resp),
//!         _ => Response::empty_404(),
//!     }
//! }
//! ```
//!
//! ### 3. Parse an incoming request using [`UncheckedProposal::from_request()`](crate::receive::UncheckedProposal::from_request())
//!
//! Parse the incoming HTTP request and check that it follows protocol.
//!
//! ```
//! let headers = Headers(req.headers());
//! let proposal = payjoin::receive::UncheckedProposal::from_request(
//!     req.data().context("Failed to read request body")?,
//!     req.raw_query_string(),
//!     headers,
//! )?;
//! ```
//!
//! Headers are parsed using the [`payjoin::receiver::Headers`] Trait so that the library can iterate through them, ideally without cloning.
//!
//! ```
//! struct Headers<'a>(rouille::HeadersIter<'a>);
//! impl payjoin::receive::Headers for Headers<'_> {
//!     fn get_header(&self, key: &str) -> Option<&str> {
//!         let mut copy = self.0.clone(); //! lol
//!         copy.find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
//!     }
//! }
//! ```
//!
//! ### 4. Validate the proposal using the `check` methods
//!
//! Check the sender's Original PSBT to prevent it from stealing, probing to fingerprint its wallet, and to avoid privacy gotchas.
//!
//! ```
//! // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
//! let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();
//!
//! // The network is used for checks later
//! let network = match bitcoind.get_blockchain_info()?.chain.as_str() {
//!     "main" => bitcoin::Network::Bitcoin,
//!     "test" => bitcoin::Network::Testnet,
//!     "regtest" => bitcoin::Network::Regtest,
//!     _ => return Err(ReceiveError::Other(anyhow!("Unknown network"))),
//! };
//! ```
//!
//! #### Check 1: Can the Original PSBT be Broadcast?
//!
//! We need to know this transaction is consensus-valid.
//!
//! ```
//! let checked_1 = proposal.check_can_broadcast(|tx| {
//!         let raw_tx = bitcoin::consensus::encode::serialize(&tx).to_hex();
//!         let mempool_results = self
//!             .bitcoind
//!             .test_mempool_accept(&[raw_tx])
//!             .map_err(|e| Error::Server(e.into()))?;
//!         match mempool_results.first() {
//!             Some(result) => Ok(result.allowed),
//!             None => Err(Error::Server(
//!                 anyhow!("No mempool results returned on broadcast check").into(),
//!             )),
//!         }
//!     })?;
//! ```
//!
//! If writing a payment processor, schedule that this transaction is broadcast as fallback if the payjoin fails after a timeout. BTCPay broadcasts fallback after two minutes.
//!
//! #### Check 2: Is the sender trying to make us sign our own inputs?
//!
//! ```
//! let checked_2 = checked_1.check_inputs_not_owned(|input| {
//!         if let Ok(address) = bitcoin::Address::from_script(input, network) {
//!             self.bitcoind
//!                 .get_address_info(&address)
//!                 .map(|info| info.is_mine.unwrap_or(false))
//!                 .map_err(|e| Error::Server(e.into()))
//!         } else {
//!             Ok(false)
//!         }
//!     })?;
//! ```
//!
//! #### Check 3: Are there mixed input scripts, breaking stenographic privacy?
//!
//! ```
//! let checked_3 = checked_2.check_no_mixed_input_scripts()?;
//! ```
//!
//! #### Check 4: Have we seen this input before?
//!
//! Non-interactive i.e. payment processors should be careful to keep track of request inputs or else a malicious sender may try and probe multiple responses containing the receiver utxos, clustering their wallet.
//!
//! ```
//! let mut checked_4 = checked_3.check_no_inputs_seen_before(|input| {
//!     Ok(!self.insert_input_seen_before(*input).map_err(|e| Error::Server(e.into()))?)
//! })?;
//! ```
//!
//! ### 5. Augment a valid proposal to preserve privacy
//!
//! Here's where the PSBT is modified. Inputs may be added to break common input ownership heurstic. There are a number of ways to select coins and break common input heuristic but fail to preserve privacy because of  Unnecessary Input Heuristic (UIH). Until February 2023, even BTCPay occasionally made these errors. Privacy preserving coin selection as implemented in `try_preserving_privacy` is precarious to implement yourself may be the most sensitive and valuable part of this kit.
//!
//! Output substitution is another way to improve privacy and increase functionality. For example, if the Original PSBT output address paying the receiver is coming from a static URI, a new address may be generated on the fly to avoid address reuse. This can even be done from a watch-only wallet. Output substitution may also be used to consolidate incoming funds to a remote cold wallet, break an output into smaller UTXOs to fulfill exchange orders, open lightning channels, and more.
//!
//! ```
//! // Distinguish our outputs to augment with input amount
//! let mut payjoin = checked_4.identify_receiver_outputs(|output_script| {
//!     if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
//!         self.bitcoind
//!             .get_address_info(&address)
//!             .map(|info| info.is_mine.unwrap_or(false))
//!             .map_err(|e| Error::Server(e.into()))
//!     } else {
//!         Ok(false)
//!     }
//! })?;
//! // Select receiver payjoin inputs.
//! _ = try_contributing_inputs(&mut payjoin, bitcoind)
//!     .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));
//!
//! let receiver_substitute_address = bitcoind.get_new_address(None, None)?;
//! payjoin.substitute_output_address(receiver_substitute_address);
//!
//! // ...
//!
//! fn try_contributing_inputs(
//!     payjoin: &mut PayjoinProposal,
//!     bitcoind: &bitcoincore_rpc::Client,
//! ) -> Result<()> {
//!     use bitcoin::OutPoint;
//!
//!     let available_inputs = bitcoind
//!         .list_unspent(None, None, None, None, None)
//!         .context("Failed to list unspent from bitcoind")?;
//!     let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
//!         .iter()
//!         .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
//!         .collect();
//!
//!     let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
//!     let selected_utxo = available_inputs
//!         .iter()
//!         .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
//!         .context("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.")?;
//!     log::debug!("selected utxo: {:#?}", selected_utxo);
//!
//!     // calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt
//!     let txo_to_contribute = bitcoin::TxOut {
//!         value: selected_utxo.amount.to_sat(),
//!         script_pubkey: selected_utxo.script_pub_key.clone(),
//!     };
//!     let outpoint_to_contribute =
//!         bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
//!     payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);
//!     Ok(())
//! }
//! ```
//!
//! Using methods for coin selection not provided by this library may have dire implications for privacy. Significant in-depth research and careful implementation iteration has gone into privacy preserving transaction construction. [Here's a good starting point from the JoinMarket repo to being a deep dive of your own](https://gist.github.com/AdamISZ/4551b947789d3216bacfcb7af25e029e#gistcomment-2796539).
//!
//! ### 6. Extract the payjoin PSBT and sign it
//!
//! Fees are applied to the augmented Payjoin Proposal PSBT using calculation factoring both receiver's preferred feerate and the sender's fee-related [optional parameters](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#optional-parameters). The current `apply_fee` method is primitive, disregarding PSBT fee estimation and only adding fees coming from the sender's budget. When more accurate tools are available to calculate a PSBT's fee-dependent weight (solved, more complicated than it sounds, but unimplemented in rust-bitcoin), this `apply_fee` should be improved.
//!
//! ```
//! let min_feerate_sat_per_vb = 1;
//! let payjoin_proposal_psbt = payjoin.apply_fee(Some(min_feerate_sat_per_vb))?;
//!
//! log::debug!("Extracted PSBT: {:#?}", payjoin_proposal_psbt);
//! // Sign payjoin psbt
//! let payjoin_base64_string =
//!     base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
//! // `wallet_process_psbt` adds available utxo data and finalizes
//! let payjoin_proposal_psbt =
//!     bitcoind.wallet_process_psbt(&payjoin_base64_string, sign: None, sighash_type: None, bip32derivs: Some(false))?.psbt;
//! let payjoin_proposal_psbt =
//!     load_psbt_from_base64(payjoin_proposal_psbt.as_bytes()).context("Failed to parse PSBT")?;
//! ```
//!
//! ### 7. Respond to the sender's http request with the signed PSBT as payload
//!
//! BIP 78 senders require specific PSBT validation constraints regulated by prepare_psbt. PSBTv0 was not designed to support input/output modification, so the protocol requires this precise preparation step. A future PSBTv2 payjoin protocol may not.
//!
//! It is critical to pay special care when returning error response messages. Responding with internal errors can make a receiver vulnerable to sender probing attacks which cluster UTXOs.
//!
//! ```
//! let payjoin_proposal_psbt = payjoin.prepare_psbt(payjoin_proposal_psbt)?;
//! let payload = base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
//! Ok(Response::text(payload))
//! ```

//! 📥 That's how one receives a payjoin.

use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};

use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{Amount, OutPoint, Script, TxOut};

mod error;
mod optional_parameters;

pub use error::{Error, RequestError, SelectionError};
use error::{InternalRequestError, InternalSelectionError};
use optional_parameters::Params;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::fee_rate::FeeRate;
use crate::input_type::InputType;
use crate::psbt::PsbtExt;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to proces the request. It is returned by
/// [`UncheckedProposal::from_request()`](crate::receive::UncheckedProposal::from_request()).
///
/// If you are implementing an interactive payment processor, you should get extract the original
/// transaction with get_transaction_to_schedule_broadcast() and schedule, followed by checking
/// that the transaction can be broadcast with check_can_broadcast. Otherwise it is safe to
/// call assume_interactive_receive to proceed with validation.
pub struct UncheckedProposal {
    psbt: Psbt,
    params: Params,
}

/// Typestate to validate that the Original PSBT has no receiver-owned inputs.
///
/// Call [`check_no_receiver_owned_inputs()`](struct.UncheckedProposal.html#method.check_no_receiver_owned_inputs) to proceed.
pub struct MaybeInputsOwned {
    psbt: Psbt,
    params: Params,
}

/// Typestate to validate that the Original PSBT has no mixed input types.
///
/// Call [`check_no_mixed_input_types`](struct.UncheckedProposal.html#method.check_no_mixed_input_scripts) to proceed.
pub struct MaybeMixedInputScripts {
    psbt: Psbt,
    params: Params,
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`check_no_inputs_seen`](struct.MaybeInputsSeen.html#method.check_no_inputs_seen_before) to proceed.
pub struct MaybeInputsSeen {
    psbt: Psbt,
    params: Params,
}

impl UncheckedProposal {
    pub fn from_request(
        body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, RequestError> {
        use crate::bitcoin::consensus::Decodable;

        let content_type = headers
            .get_header("content-type")
            .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
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
        let mut reader = base64::read::DecoderReader::new(&mut limited, base64::STANDARD);
        let unchecked_psbt =
            Psbt::consensus_decode(&mut reader).map_err(InternalRequestError::Decode)?;
        let psbt = unchecked_psbt.validate().map_err(InternalRequestError::Psbt)?;
        log::debug!("Received original psbt: {:?}", psbt);

        let pairs = url::form_urlencoded::parse(query.as_bytes());
        let params = Params::from_query_pairs(pairs).map_err(InternalRequestError::SenderParams)?;
        log::debug!("Received request with params: {:?}", params);

        // TODO check that params are valid for the request's Original PSBT

        Ok(UncheckedProposal { psbt, params })
    }

    /// The Sender's Original PSBT
    pub fn get_transaction_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `get_transaction_to_check_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_can_broadcast(
        self,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, Error>,
    ) -> Result<MaybeInputsOwned, Error> {
        if can_broadcast(&self.psbt.clone().extract_tx())? {
            Ok(MaybeInputsOwned { psbt: self.psbt, params: self.params })
        } else {
            Err(Error::BadRequest(InternalRequestError::OriginalPsbtNotBroadcastable.into()))
        }
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt, params: self.params }
    }
}

impl MaybeInputsOwned {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<MaybeMixedInputScripts, Error> {
        let mut err = Ok(());
        if let Some(e) = self
            .psbt
            .input_pairs()
            .scan(&mut err, |err, input| match input.previous_txout() {
                Ok(txout) => Some(txout.script_pubkey.to_owned()),
                Err(e) => {
                    **err = Err(Error::BadRequest(InternalRequestError::PrevTxOut(e).into()));
                    None
                }
            })
            .find_map(|script| match is_owned(&script) {
                Ok(false) => None,
                Ok(true) =>
                    Some(Error::BadRequest(InternalRequestError::InputOwned(script).into())),
                Err(e) => Some(Error::Server(e.into())),
            })
        {
            return Err(e);
        }
        err?;

        Ok(MaybeMixedInputScripts { psbt: self.psbt, params: self.params })
    }
}

impl MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(self) -> Result<MaybeInputsSeen, RequestError> {
        let mut err = Ok(());
        let input_scripts = self
            .psbt
            .input_pairs()
            .scan(&mut err, |err, input| match input.previous_txout() {
                Ok(txout) => match InputType::from_spent_input(txout, input.psbtin) {
                    Ok(input_script) => Some(input_script),
                    Err(e) => {
                        **err = Err(RequestError::from(InternalRequestError::InputType(e)));
                        None
                    }
                },
                Err(e) => {
                    **err = Err(RequestError::from(InternalRequestError::PrevTxOut(e)));
                    None
                }
            })
            .collect::<Vec<_>>();
        err?;

        if let Some(first) = input_scripts.first() {
            input_scripts.iter().try_for_each(|input_type| {
                if input_type != first {
                    Err(RequestError::from(InternalRequestError::MixedInputScripts(
                        *first,
                        *input_type,
                    )))
                } else {
                    Ok(())
                }
            })?;
        }

        Ok(MaybeInputsSeen { psbt: self.psbt, params: self.params })
    }
}

impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, Error>,
    ) -> Result<OutputsUnknown, Error> {
        self.psbt.input_pairs().try_for_each(|input| {
            match is_known(&input.txin.previous_output) {
                Ok(false) => Ok::<(), Error>(()),
                Ok(true) =>  {
                    log::warn!("Request contains an input we've seen before: {}. Preventing possible probing attack.", input.txin.previous_output);
                    Err(Error::BadRequest(
                        InternalRequestError::InputSeen(input.txin.previous_output).into(),
                    ))?
                },
                Err(e) => Err(Error::Server(e.into()))?,
            }
        })?;

        Ok(OutputsUnknown { psbt: self.psbt, params: self.params })
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
pub struct OutputsUnknown {
    psbt: Psbt,
    params: Params,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<PayjoinProposal, Error> {
        let owned_vouts: Vec<usize> = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(vout, txo)| match is_receiver_output(&txo.script_pubkey) {
                Ok(true) => Some(Ok(vout)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        if owned_vouts.is_empty() {
            return Err(Error::BadRequest(InternalRequestError::MissingPayment.into()));
        }

        Ok(PayjoinProposal {
            original_psbt: self.psbt.clone(),
            payjoin_psbt: self.psbt,
            params: self.params,
            owned_vouts,
        })
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
pub struct PayjoinProposal {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
    params: Params,
    owned_vouts: Vec<usize>,
}

impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.payjoin_psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.params.disable_output_substitution
    }

    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblence, a number of heuristics must be avoided.
    ///
    /// UIH "Unecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    // if min(out) < min(in) then UIH1 else UIH2
    // https://eprint.iacr.org/2022/589.pdf
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: HashMap<Amount, OutPoint>,
    ) -> Result<OutPoint, SelectionError> {
        if candidate_inputs.is_empty() {
            return Err(SelectionError::from(InternalSelectionError::Empty));
        }

        if self.payjoin_psbt.outputs.len() != 2 {
            // Current UIH techniques only support many-input, two-output transactions.
            return Err(SelectionError::from(InternalSelectionError::TooManyOutputs));
        }

        let min_original_out_sats = self
            .payjoin_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value)
            .min()
            .unwrap_or_else(|| Amount::MAX_MONEY.to_sat());

        let min_original_in_sats = self
            .payjoin_psbt
            .input_pairs()
            .filter_map(|input| input.previous_txout().ok().map(|txo| txo.value))
            .min()
            .unwrap_or_else(|| Amount::MAX_MONEY.to_sat());

        // Assume many-input, two output to select the vout for now
        let prior_payment_sats = self.payjoin_psbt.unsigned_tx.output[self.owned_vouts[0]].value;
        for candidate in candidate_inputs {
            // TODO bound loop by timeout / iterations

            let candidate_sats = candidate.0.to_sat();
            let candidate_min_out = min(min_original_out_sats, prior_payment_sats + candidate_sats);
            let candidate_min_in = min(min_original_in_sats, candidate_sats);

            if candidate_min_out < candidate_min_in {
                // The candidate avoids UIH2 but conforms to UIH1: Optimal change heuristic.
                // It implies the smallest output is the sender's change address.
                return Ok(candidate.1);
            } else {
                // The candidate conforms to UIH2: Unnecessary input
                // and could be identified as a potential payjoin
                continue;
            }
        }

        // No suitable privacy preserving selection found
        Err(SelectionError::from(InternalSelectionError::NotFound))
    }

    pub fn contribute_witness_input(&mut self, txo: TxOut, outpoint: OutPoint) {
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence = self
            .payjoin_psbt
            .unsigned_tx
            .input
            .first()
            .map(|input| input.sequence)
            .unwrap_or_default();

        // Add the value of new receiver input to receiver output
        let txo_value = txo.value;
        let vout_to_augment =
            self.owned_vouts.choose(&mut rand::thread_rng()).expect("owned_vouts is empty");
        self.payjoin_psbt.unsigned_tx.output[*vout_to_augment].value += txo_value;

        // Insert contribution at random index for privacy
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..=self.payjoin_psbt.unsigned_tx.input.len());
        self.payjoin_psbt
            .inputs
            .insert(index, bitcoin::psbt::Input { witness_utxo: Some(txo), ..Default::default() });
        self.payjoin_psbt.unsigned_tx.input.insert(
            index,
            bitcoin::TxIn {
                previous_output: outpoint,
                sequence: original_sequence,
                ..Default::default()
            },
        );
    }

    pub fn contribute_non_witness_input(&mut self, tx: bitcoin::Transaction, outpoint: OutPoint) {
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence = self
            .payjoin_psbt
            .unsigned_tx
            .input
            .first()
            .map(|input| input.sequence)
            .unwrap_or_default();

        // Add the value of new receiver input to receiver output
        let txo_value = tx.output[outpoint.vout as usize].value;
        let vout_to_augment =
            self.owned_vouts.choose(&mut rand::thread_rng()).expect("owned_vouts is empty");
        self.payjoin_psbt.unsigned_tx.output[*vout_to_augment].value += txo_value;

        // Insert contribution at random index for privacy
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..=self.payjoin_psbt.unsigned_tx.input.len());

        // Add the new input to the PSBT
        self.payjoin_psbt.inputs.insert(
            index,
            bitcoin::psbt::Input { non_witness_utxo: Some(tx), ..Default::default() },
        );
        self.payjoin_psbt.unsigned_tx.input.insert(
            index,
            bitcoin::TxIn {
                previous_output: outpoint,
                sequence: original_sequence,
                ..Default::default()
            },
        );
    }

    /// Just replace an output address with
    pub fn substitute_output_address(&mut self, substitute_address: bitcoin::Address) {
        self.payjoin_psbt.unsigned_tx.output[self.owned_vouts[0]].script_pubkey =
            substitute_address.script_pubkey();
    }

    /// Apply additional fee contribution now that the receiver has contributed input
    /// this is kind of a "build_proposal" step before we sign and finalize and extract
    ///
    /// WARNING: DO NOT ALTER INPUTS OR OUTPUTS AFTER THIS STEP
    pub fn apply_fee(
        &mut self,
        min_feerate_sat_per_vb: Option<u64>,
    ) -> Result<&Psbt, RequestError> {
        let min_feerate =
            FeeRate::from_sat_per_vb_unchecked(min_feerate_sat_per_vb.unwrap_or_default());
        log::trace!("min_feerate: {:?}", min_feerate);
        log::trace!("params.min_feerate: {:?}", self.params.min_feerate);
        let min_feerate = max(min_feerate, self.params.min_feerate);
        log::debug!("min_feerate: {:?}", min_feerate);

        // this error should never happen. We check for at least one input in the constructor
        let input_pair = self
            .payjoin_psbt
            .input_pairs()
            .next()
            .ok_or(InternalRequestError::OriginalPsbtNotBroadcastable)?;
        let txo = input_pair.previous_txout().map_err(InternalRequestError::PrevTxOut)?;
        let input_type = InputType::from_spent_input(txo, &self.payjoin_psbt.inputs[0])
            .map_err(InternalRequestError::InputType)?;
        let contribution_weight = input_type.expected_input_weight();
        log::trace!("contribution_weight: {}", contribution_weight);
        let mut additional_fee = contribution_weight * min_feerate;
        let max_additional_fee_contribution =
            self.params.additional_fee_contribution.unwrap_or_default().0;
        if additional_fee >= max_additional_fee_contribution {
            // Cap fee at the sender's contribution to simplify this method
            additional_fee = max_additional_fee_contribution;
        }
        log::trace!("additional_fee: {}", additional_fee);
        if additional_fee > bitcoin::Amount::ZERO {
            log::trace!(
                "self.params.additional_fee_contribution: {:?}",
                self.params.additional_fee_contribution
            );
            if let Some((_, additional_fee_output_index)) = self.params.additional_fee_contribution
            {
                if !self.owned_vouts.contains(&additional_fee_output_index) {
                    // remove additional miner fee from the sender's specified output
                    self.payjoin_psbt.unsigned_tx.output[additional_fee_output_index].value -=
                        additional_fee.to_sat();
                }
            }
        }
        Ok(&self.payjoin_psbt)
    }

    /// Return a Payjoin Proposal PSBT that the sender will find acceptable.
    ///
    /// This attempts to calculate any network fee owed by the receiver, subtract it from their output,
    /// and return a PSBT that can produce a consensus-valid transaction that the sender will accept.
    ///
    /// wallet_process_psbt should sign and finalize receiver inputs
    pub fn prepare_psbt(mut self, processed_psbt: Psbt) -> Result<Psbt, RequestError> {
        self.payjoin_psbt = processed_psbt;
        log::trace!("Preparing PSBT {:#?}", self.payjoin_psbt);
        for input in self.payjoin_psbt.inputs_mut() {
            input.bip32_derivation = BTreeMap::new();
            input.partial_sigs = BTreeMap::new();
        }
        // iterate proposal as mutable WITH the outpoint (previous_output) available too
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut sender_input_indexes = vec![];
        for (i, input) in self.payjoin_psbt.input_pairs().enumerate() {
            if let Some(original) = original_inputs.peek() {
                log::trace!(
                    "match previous_output: {} == {}",
                    input.txin.previous_output,
                    original.txin.previous_output
                );
                if input.txin.previous_output == original.txin.previous_output {
                    sender_input_indexes.push(i);
                    original_inputs.next();
                }
            }
        }

        for i in sender_input_indexes {
            log::trace!("Clearing sender input {}", i);
            self.payjoin_psbt.inputs[i].non_witness_utxo = None;
            self.payjoin_psbt.inputs[i].witness_utxo = None;
            self.payjoin_psbt.inputs[i].final_script_sig = None;
            self.payjoin_psbt.inputs[i].final_script_witness = None;
        }
        Ok(self.payjoin_psbt)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        #[cfg(test)]
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    fn get_proposal_from_test_vector() -> Result<UncheckedProposal, RequestError> {
        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let body = original_psbt.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        UncheckedProposal::from_request(
            body,
            "?maxadditionalfeecontribution=182?additionalfeeoutputindex=0",
            headers,
        )
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = get_proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        use std::str::FromStr;

        use bitcoin::{Address, Network};

        let proposal = get_proposal_from_test_vector().unwrap();
        let mut payjoin = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| Ok(false))
            .expect("No inputs should be owned")
            .check_no_mixed_input_scripts()
            .expect("No mixed input scripts")
            .check_no_inputs_seen_before(|_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(|script| {
                Ok(Address::from_script(script, Network::Bitcoin)
                    == Address::from_str(&"3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM"))
            })
            .expect("Receiver output should be identified");
        let payjoin = payjoin.apply_fee(None);

        assert!(payjoin.is_ok(), "Payjoin should be a valid PSBT");
    }
}
