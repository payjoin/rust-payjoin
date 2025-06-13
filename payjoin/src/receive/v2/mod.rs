//! Receive BIP 77 Payjoin v2
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
pub use persist::{ReceiverToken, SessionEvent};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Error, InputContributionError};
use super::{
    v1, InternalPayloadError, JsonReply, OutputSubstitutionError, ReplyableError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{
    ohttp_encapsulate, process_get_res, process_post_res, OhttpEncapsulationError, OhttpKeys,
};
use crate::output_substitution::OutputSubstitution;
use crate::persist::Persister;
use crate::receive::{parse_payload, InputPair};
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, Request, Version};

mod error;
mod persist;

const SUPPORTED_VERSIONS: &[Version] = &[Version::One, Version::Two];

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: url::Url,
    subdirectory: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    s: HpkeKeyPair,
    e: Option<HpkePublicKey>,
}

impl SessionContext {
    fn full_relay_url(&self, ohttp_relay: impl IntoUrl) -> Result<Url, InternalSessionError> {
        let relay_base = ohttp_relay.into_url().map_err(InternalSessionError::ParseUrl)?;

        // Only reveal scheme and authority to the relay
        let directory_base =
            self.directory.join("/").map_err(|e| InternalSessionError::ParseUrl(e.into()))?;

        // Append that information as a path to the relay URL
        relay_base
            .join(&format!("/{directory_base}"))
            .map_err(|e| InternalSessionError::ParseUrl(e.into()))
    }

    /// The per-session identifier
    pub(crate) fn id(&self) -> ShortId {
        sha256::Hash::hash(&self.s.public_key().to_compressed_bytes()).into()
    }
}

fn deserialize_address_assume_checked<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let address = Address::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(address.assume_checked())
}

fn subdir_path_from_pubkey(pubkey: &HpkePublicKey) -> ShortId {
    sha256::Hash::hash(&pubkey.to_compressed_bytes()).into()
}

/// A new payjoin receiver, which must be persisted before initiating the payjoin flow.
#[derive(Debug)]
pub struct NewReceiver {
    context: SessionContext,
}

impl NewReceiver {
    /// Creates a new [`NewReceiver`] with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `expire_after`: The duration after which the session expires.
    ///
    /// # Returns
    /// A new instance of [`NewReceiver`].
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
    pub fn new(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        expire_after: Option<Duration>,
    ) -> Result<Self, IntoUrlError> {
        let receiver = Self {
            context: SessionContext {
                address,
                directory: directory.into_url()?,
                subdirectory: None,
                ohttp_keys,
                expiry: SystemTime::now()
                    + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
        };
        Ok(receiver)
    }

    /// Saves the new [`Receiver`] using the provided persister and returns the storage token.
    pub fn persist<P: Persister<Receiver<WithContext>>>(
        &self,
        persister: &mut P,
    ) -> Result<P::Token, ImplementationError> {
        let receiver = Receiver { state: WithContext { context: self.context.clone() } };
        Ok(persister.save(receiver)?)
    }
}

pub trait ReceiverState {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver<State: ReceiverState> {
    pub(crate) state: State,
}

impl<State: ReceiverState> core::ops::Deref for Receiver<State> {
    type Target = State;

    fn deref(&self) -> &Self::Target { &self.state }
}

impl<State: ReceiverState> core::ops::DerefMut for Receiver<State> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.state }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithContext {
    context: SessionContext,
}

impl ReceiverState for WithContext {}

impl Receiver<WithContext> {
    /// Loads a [`Receiver`] from the provided persister using the storage token.
    pub fn load<P: Persister<Receiver<WithContext>>>(
        token: P::Token,
        persister: &P,
    ) -> Result<Self, ImplementationError> {
        persister.load(token).map_err(ImplementationError::from)
    }
    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        if SystemTime::now() > self.context.expiry {
            return Err(InternalSessionError::Expired(self.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<Receiver<UncheckedProposal>>, Error> {
        let body = match process_get_res(body, context)
            .map_err(InternalSessionError::DirectoryResponse)?
        {
            Some(body) => body,
            None => return Ok(None),
        };
        match std::str::from_utf8(&body) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(Receiver { state: self.extract_proposal_from_v1(response)? })),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(Receiver { state: self.extract_proposal_from_v2(body)? })),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = subdir(&self.context.directory, &self.context.id());
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        &mut self,
        response: &str,
    ) -> Result<UncheckedProposal, ReplyableError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(&mut self, response: Vec<u8>) -> Result<UncheckedProposal, Error> {
        let (payload_bytes, e) = decrypt_message_a(&response, self.context.s.secret_key().clone())?;
        self.context.e = Some(e);
        let payload = std::str::from_utf8(&payload_bytes)
            .map_err(|e| Error::ReplyToSender(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map_err(Error::ReplyToSender)
    }

    fn unchecked_from_payload(
        &mut self,
        payload: &str,
    ) -> Result<UncheckedProposal, ReplyableError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {query}, base64: {base64}"); // my guess is no \n so default is wrong
        let (psbt, mut params) =
            parse_payload(base64, query, SUPPORTED_VERSIONS).map_err(ReplyableError::Payload)?;

        // Output substitution must be disabled for V1 sessions in V2 contexts.
        //
        // V2 contexts depend on a payjoin directory to store and forward payjoin
        // proposals. Plaintext V1 proposals are vulnerable to output replacement
        // attacks by a malicious directory if output substitution is not disabled.
        // V2 proposals are authenticated and encrypted to prevent such attacks.
        //
        // see: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server
        if params.v == Version::One {
            params.output_substitution = OutputSubstitution::Disabled;

            // Additionally V1 sessions never have an optimistic merge opportunity
            #[cfg(feature = "_multiparty")]
            {
                params.optimistic_merge = false;
            }
        }

        let inner = v1::UncheckedProposal { psbt, params };
        Ok(UncheckedProposal { v1: inner, context: self.context.clone() })
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        use crate::uri::{PayjoinExtras, UrlExt};
        let mut pj = subdir(&self.context.directory, &self.context.id()).clone();
        pj.set_receiver_pubkey(self.context.s.public_key().clone());
        pj.set_ohttp(self.context.ohttp_keys.clone());
        pj.set_exp(self.context.expiry);
        let extras =
            PayjoinExtras { endpoint: pj, output_substitution: OutputSubstitution::Enabled };
        bitcoin_uri::Uri::with_extras(self.context.address.clone(), extras)
    }
}

/// The original PSBT and the optional parameters received from the sender.
///
/// This is the earliest typestate in the receiver workflow. At this stage,
/// the receiver can verify that the original PSBT they have received from the sender
/// is broadcastable to the network in the case of a payjoin failure.
///
/// The recommended usage of this typestate differs based on whether you are implementing an
/// interactive (where the receiver takes manual actions to respond to the``
/// payjoin proposal) or a non-interactive (ex. a donation page which automatically generates a new QR code
/// for each visit) payment receiver. For the latter, you should call [`Receiver<UncheckedProposal>::extract_tx_to_schedule_broadcast`] and
/// schedule the broadcast of the sender proposal, followed by [`Receiver<UncheckedProposal>::check_broadcast_suitability`] to check
/// that the proposal is actually broadcastable (and, optionally, whether the fee rate is above the
/// minimum limit you have set). These mechanisms protect the receiver against probing attacks, where
/// a malicious sender can repeatedly send proposals to have the non-interactive receiver reveal the UTXOs
/// it owns with the proposals it modifies.
///
/// If you are implementing an interactive payment receiver, then such checks are not necessary, and you
/// can go ahead with calling [`Receiver<UncheckedProposal>::assume_interactive_receiver`] to move on to the next typestate.
#[derive(Debug, Clone)]
pub struct UncheckedProposal {
    pub(crate) v1: v1::UncheckedProposal,
    pub(crate) context: SessionContext,
}

impl ReceiverState for UncheckedProposal {}

impl Receiver<UncheckedProposal> {
    /// Extracts the original transaction received from the sender.
    ///
    /// Use this for scheduling the broadcast of the original transaction as a fallback
    /// for the payjoin. Note that this function does not make any validation on whether
    /// the transaction is broadcastable; it simply extracts it.
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.v1.extract_tx_to_schedule_broadcast()
    }

    /// Checks that the original PSBT in the proposal can be broadcasted.
    ///
    /// If the receiver is a non-interactive payment processor (ex. a donation page which generates
    /// a new QR code for each visit), then it should make sure that the original PSBT is broadcastable
    /// as a fallback mechanism in case the payjoin fails. This validation would be equivalent to
    /// `testmempoolaccept` RPC call returning `{"allowed": true,...}`.
    ///
    /// Receiver can optionally set a minimum fee rate which will be enforced on the original PSBT in the proposal.
    /// This can be used to further prevent probing attacks since the attacker would now need to probe the receiver
    /// with transactions which are both broadcastable and pay high fee. Unrelated to the probing attack scenario,
    /// this parameter also makes operating in a high fee environment easier for the receiver.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<MaybeInputsOwned>, ReplyableError> {
        let inner = self.state.v1.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(Receiver { state: MaybeInputsOwned { v1: inner, context: self.state.context } })
    }

    /// Moves on to the next typestate without any of the current typestate's validations.
    ///
    /// Use this for interactive payment receivers, where there is no risk of a probing attack since the
    /// receiver needs to manually respond to each payjoin proposal.
    pub fn assume_interactive_receiver(self) -> Receiver<MaybeInputsOwned> {
        let inner = self.state.v1.assume_interactive_receiver();
        Receiver { state: MaybeInputsOwned { v1: inner, context: self.state.context } }
    }

    /// Extract an OHTTP Encapsulated HTTP POST request to return
    /// a Receiver Error Response
    pub fn extract_err_req(
        &mut self,
        err: &JsonReply,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        let subdir = subdir(&self.context.directory, &self.context.id());
        let (body, ohttp_ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "POST",
            subdir.as_str(),
            Some(err.to_json().to_string().as_bytes()),
        )
        .map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process an OHTTP Encapsulated HTTP POST Error response
    /// to ensure it has been posted properly
    pub fn process_err_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<(), SessionError> {
        process_post_res(body, context)
            .map_err(|e| InternalSessionError::DirectoryResponse(e).into())
    }
}

/// Typestate to check that the original PSBT has no inputs owned by the receiver.
///
/// Call [`Receiver<MaybeInputsOwned>::check_inputs_not_owned`] to proceed with the next typestate.
#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    context: SessionContext,
}

impl ReceiverState for MaybeInputsOwned {}

impl Receiver<MaybeInputsOwned> {
    /// Checks that the original PSBT has no inputs owned by the receiver.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<MaybeInputsSeen>, ReplyableError> {
        let inner = self.state.v1.check_inputs_not_owned(is_owned)?;
        Ok(Receiver { state: MaybeInputsSeen { v1: inner, context: self.state.context } })
    }
}

/// Typestate to check that the original PSBT has no inputs that the receiver has seen before.
///
/// Call [`Receiver<MaybeInputsSeen>::check_no_inputs_seen_before`] to proceed with the next
/// typestate.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    context: SessionContext,
}

impl ReceiverState for MaybeInputsSeen {}

impl Receiver<MaybeInputsSeen> {
    /// Check that the receiver has never seen the inputs in the original proposal before.
    ///
    /// This check prevents the following attacks:
    /// 1. Probing attacks, where the sender can use the exact same proposal (or with minimal change)
    ///    to have the receiver reveal their UTXO set by contributing to all proposals with different inputs
    ///    and sending them back to the receiver.
    /// 2. Re-entrant payjoin, where the sender uses the payjoin PSBT of a previous payjoin as the
    ///    original proposal PSBT of the current, new payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<OutputsUnknown>, ReplyableError> {
        let inner = self.state.v1.check_no_inputs_seen_before(is_known)?;
        Ok(Receiver { state: OutputsUnknown { inner, context: self.state.context } })
    }
}
/// Typestate to check that the outputs of the original PSBT actually pay to the receiver.
///
/// The receiver should only accept the original PSBTs from the sender which actually send them
/// money.
///
/// Identify those outputs with [`Receiver<OutputsUnknown>::identify_receiver_outputs`] and proceed
/// with the next typestate.
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    inner: v1::OutputsUnknown,
    context: SessionContext,
}

impl ReceiverState for OutputsUnknown {}

impl Receiver<OutputsUnknown> {
    /// Validates whether the original PSBT contains outputs which pays to the receiver and only
    /// then allows continuing with the next typestate.
    ///
    /// Additionally, this function also checks whether the sender did not point to an output
    /// which pays to the receiver when specifying an output the receiver can reduce the value of
    /// to increase the fees the transaction pays. If the parameter does point to a output which
    /// pays to the receiver, this function sets the parameter to None before letting the receive
    /// process continue to the next steps, protecting the receiver from accidentally subtracting fees
    /// from their own outputs.
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<WantsOutputs>, ReplyableError> {
        let inner = self.state.inner.identify_receiver_outputs(is_receiver_output)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context } })
    }
}

/// A checked proposal that the receiver may substitute or add outputs to
///
/// Call [`Receiver<WantsOutputs>::commit_outputs`] to proceed.
#[derive(Debug, Clone)]
pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    context: SessionContext,
}

impl ReceiverState for WantsOutputs {}

impl Receiver<WantsOutputs> {
    /// Whether the receiver is allowed to substitute original outputs or not.
    pub fn output_substitution(&self) -> OutputSubstitution { self.v1.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.substitute_receiver_script(output_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context } })
    }
    /// Replaces **all** receiver outputs with the one or more provided `replacement_outputs`, and
    /// sets up the passed `drain_script` as the receiver-owned output which might have its value
    /// adjusted based on the modifications the receiver makes in the subsequent typestates.
    ///
    /// Sender's outputs are not touched. Existing receiver outputs will be replaced with the
    /// outputs in the `replacement_outputs` argument. The number of replacement outputs should
    /// match or exceed the number of receiver outputs in the original proposal PSBT.
    ///
    /// The drain script is the receiver script which will have its value adjusted based on the
    /// modifications the receiver makes on the transaction in the subsequent typestates. For
    /// example, if the receiver adds their own input, then the drain script output will have its
    /// value increased by the same amount. Or if an output needs to have its value reduced to
    /// account for fees, the value of the output for this script will be reduced.
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: impl IntoIterator<Item = TxOut>,
        drain_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context } })
    }

    /// Commits the outputs as final, and moves on to the next typestate.
    ///
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> Receiver<WantsInputs> {
        let inner = self.state.v1.commit_outputs();
        Receiver { state: WantsInputs { v1: inner, context: self.state.context } }
    }
}

/// Typestate for a checked proposal which the receiver may contribute inputs to.
///
/// Call [`Receiver<WantsOutputs>::commit_inputs`] to proceed.
#[derive(Debug, Clone)]
pub struct WantsInputs {
    v1: v1::WantsInputs,
    context: SessionContext,
}

impl ReceiverState for WantsInputs {}

impl Receiver<WantsInputs> {
    /// Selects and returns an input from `candidate_inputs` which will preserve the receiver's privacy by
    /// avoiding the Unnecessary Input Heuristic 2 (UIH2) outlined in [Unnecessary Input
    /// Heuristics and PayJoin Transactions by Ghesmati et al. (2022)](https://eprint.iacr.org/2022/589).
    ///
    /// Privacy preservation is only supported for 2-output transactions. If the PSBT has more than
    /// 2 outputs or if none of the candidates are suitable for avoiding UIH2, this function
    /// defaults to the first candidate in `candidate_inputs` list.
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        self.v1.try_preserving_privacy(candidate_inputs)
    }

    /// Contributes the provided list of inputs to the transaction at random indices. If the total input
    /// amount exceeds the total output amount after the contribution, adds all excess amount to
    /// the receiver change output.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Self, InputContributionError> {
        let inner = self.state.v1.contribute_inputs(inputs)?;
        Ok(Receiver { state: WantsInputs { v1: inner, context: self.state.context } })
    }

    /// Commits the inputs as final, and moves on to the next typestate.
    ///
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> Receiver<ProvisionalProposal> {
        let inner = self.state.v1.commit_inputs();
        Receiver { state: ProvisionalProposal { v1: inner, context: self.state.context } }
    }
}

/// Typestate for a checked proposal which had both the outputs and the inputs modified/contributed
/// by the receiver. The receiver may sign and finalize the Payjoin proposal which will be sent to
/// the sender for their signature.
///
/// Call [`Receiver<ProvisionalProposal>::finalize_proposal`] to return a finalized [`PayjoinProposal`].
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    context: SessionContext,
}

impl ReceiverState for ProvisionalProposal {}

impl Receiver<ProvisionalProposal> {
    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they re-sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of multiple steps: (1) subtract from the receiver outputs (and, if allowed
    /// by the sender, from their's) the fee costs to cover for the new inputs and/or outputs;
    /// (2) remove all sender signatures which were received with the original PSBT as these signatures are now invalid;
    /// (3) sign the resulting PSBT using the passed `wallet_process_psbt` signing function.
    ///
    /// How much the receiver ends up paying for fees depends on how much the sender stated they
    /// were willing to pay in the parameters of the original proposal. For additional
    /// inputs, fees will be subtracted from the sender's outputs as much as possible until we hit
    /// the limit the sender specified in the Payjoin parameters. Any remaining fees for the new inputs
    /// will be then subtracted from the change output of the receiver.
    ///
    /// Fees for additional outputs are always subtracted from the receiver's outputs.
    ///
    /// The minimum effective fee limit is the highest of the minimum limit set by the sender in
    /// the original proposal parameters and the limit passed in the `min_fee_rate` parameter.
    ///
    /// Errors if the final effective fee rate exceeds `max_effective_fee_rate`.
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<Receiver<PayjoinProposal>, ReplyableError> {
        let inner = self.state.v1.finalize_proposal(
            wallet_process_psbt,
            min_fee_rate,
            max_effective_fee_rate,
        )?;
        Ok(Receiver { state: PayjoinProposal { v1: inner, context: self.state.context } })
    }
}

/// A finalized payjoin proposal, complete with fees and receiver signatures, that the sender
/// should find acceptable.
#[derive(Clone)]
pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    context: SessionContext,
}

impl ReceiverState for PayjoinProposal {}

impl PayjoinProposal {
    #[cfg(feature = "_multiparty")]
    // TODO hack to get multi party working. A better solution would be to allow extract_req to be separate from the rest of the v2 context
    pub(crate) fn new(v1: v1::PayjoinProposal, context: SessionContext) -> Self {
        Self { v1, context }
    }
}

impl Receiver<PayjoinProposal> {
    #[cfg(feature = "_multiparty")]
    pub(crate) fn new(proposal: PayjoinProposal) -> Self { Receiver { state: proposal } }

    /// The UTXOs that would be spent by this Payjoin transaction.
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.v1.utxos_to_be_locked()
    }

    /// The Payjoin Proposal PSBT.
    pub fn psbt(&self) -> &Psbt { self.v1.psbt() }

    /// Extract an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.v1.psbt().serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource = self
                .context
                .directory
                .join(&sender_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.v1.psbt().to_string().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.context.s.public_key());
            target_resource = self
                .context
                .directory
                .join(&receiver_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;

        let req = Request::new_v2(&self.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ctx))
    }

    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        process_post_res(res, ohttp_context)
            .map_err(|e| InternalSessionError::DirectoryResponse(e).into())
    }
}

/// The subdirectory for this Payjoin receiver session.
/// It consists of a directory URL and the session ShortID in the path.
fn subdir(directory: &Url, id: &ShortId) -> Url {
    let mut url = directory.clone();
    {
        let mut path_segments =
            url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
        path_segments.push(&id.to_string());
    }
    url
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use once_cell::sync::Lazy;
    use payjoin_test_utils::{BoxError, EXAMPLE_URL, KEM, KEY_ID, SYMMETRIC};

    use super::*;
    use crate::persist::Value;

    pub(crate) static SHARED_CONTEXT: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        subdirectory: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        s: HpkeKeyPair::gen_keypair(),
        e: None,
    });

    pub(crate) static SHARED_CONTEXT_TWO: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1qv7scm7gxs32qg3lnm9kf267kllc63yvdxyh72e")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        subdirectory: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        s: HpkeKeyPair::gen_keypair(),
        e: None,
    });

    #[test]
    fn extract_err_req() -> Result<(), BoxError> {
        let mut proposal = Receiver {
            state: UncheckedProposal {
                v1: crate::receive::v1::test::unchecked_proposal_from_test_vector(),
                context: SHARED_CONTEXT.clone(),
            },
        };

        let server_error = || {
            proposal
                .clone()
                .check_broadcast_suitability(None, |_| Err("mock error".into()))
                .expect_err("expected broadcast suitability check to fail")
        };

        let expected_json = serde_json::json!({
            "errorCode": "unavailable",
            "message": "Receiver error"
        });

        let actual_json = JsonReply::from(server_error()).to_json().clone();
        assert_eq!(actual_json, expected_json);

        let (_req, _ctx) =
            proposal.clone().extract_err_req(&server_error().into(), &*EXAMPLE_URL)?;

        let internal_error: ReplyableError = InternalPayloadError::MissingPayment.into();
        let (_req, _ctx) = proposal.extract_err_req(&internal_error.into(), &*EXAMPLE_URL)?;
        Ok(())
    }

    #[test]
    fn default_expiry() {
        let now = SystemTime::now();

        let session = NewReceiver::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
            None,
        );
        let session_expiry = session.unwrap().context.expiry.duration_since(now).unwrap().as_secs();
        let default_expiry = Duration::from_secs(86400);
        if let Some(expected_expiry) = now.checked_add(default_expiry) {
            assert_eq!(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY, default_expiry);
            assert_eq!(session_expiry, expected_expiry.duration_since(now).unwrap().as_secs());
        }
    }

    #[test]
    fn receiver_ser_de_roundtrip() -> Result<(), serde_json::Error> {
        let session = Receiver { state: WithContext { context: SHARED_CONTEXT.clone() } };
        let short_id = &session.context.id();
        assert_eq!(session.key().as_ref(), short_id.as_bytes());
        let serialized = serde_json::to_string(&session)?;
        let deserialized: Receiver<WithContext> = serde_json::from_str(&serialized)?;
        assert_eq!(session, deserialized);
        Ok(())
    }

    #[test]
    fn test_v2_pj_uri() {
        let uri = Receiver { state: WithContext { context: SHARED_CONTEXT.clone() } }.pj_uri();
        assert_ne!(uri.extras.endpoint, EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Enabled);
    }
}
