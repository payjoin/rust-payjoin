use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use super::v2::error::{InternalSessionError, SessionError};
use super::{
    Error, InputContributionError, InternalRequestError, OutputSubstitutionError, RequestError,
    SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate, OhttpEncapsulationError, OhttpKeys};
use crate::psbt::PsbtExt;
use crate::receive::optional_parameters::Params;
use crate::receive::InputPair;
use crate::{PjUriBuilder, Request};

pub(crate) mod error;

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: url::Url,
    subdirectory: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    ohttp_relay: url::Url,
    s: HpkeKeyPair,
    e: Option<HpkePublicKey>,
}

fn deserialize_address_assume_checked<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let address = Address::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(address.assume_checked())
}

fn subdir_path_from_pubkey(pubkey: &HpkePublicKey) -> String {
    let hash = sha256::Hash::hash(&pubkey.to_compressed_bytes());
    BASE64_URL_SAFE_NO_PAD.encode(&hash.as_byte_array()[..8])
}

/// A payjoin V2 receiver, allowing for polled requests to the
/// payjoin directory and response processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver {
    context: SessionContext,
}

impl Receiver {
    /// Creates a new `Receiver` with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `ohttp_relay`: The URL of the OHTTP relay, used to keep client IP address confidential.
    /// - `expire_after`: The duration after which the session expires.
    ///
    /// # Returns
    /// A new instance of `Receiver`.
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/pull/1483)
    pub fn new(
        address: Address,
        directory: Url,
        ohttp_keys: OhttpKeys,
        ohttp_relay: Url,
        expire_after: Option<Duration>,
    ) -> Self {
        Self {
            context: SessionContext {
                address,
                directory,
                subdirectory: None,
                ohttp_keys,
                ohttp_relay,
                expiry: SystemTime::now()
                    + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
        }
    }

    /// Extratct an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(&mut self) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        if SystemTime::now() > self.context.expiry {
            return Err(InternalSessionError::Expired(self.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let url = self.context.ohttp_relay.clone();
        let req = Request::new_v2(url, body);
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        mut body: impl std::io::Read, // FIXME: could be &[u8], not streamed
        context: ohttp::ClientResponse,
    ) -> Result<Option<UncheckedProposal>, Error> {
        let mut buf = Vec::new();
        let _ = body.read_to_end(&mut buf);
        log::trace!("decapsulating directory response");
        let response = ohttp_decapsulate(context, &buf)?;
        if response.body().is_empty() {
            log::debug!("response is empty");
            return Ok(None);
        }
        match String::from_utf8(response.body().to_vec()) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(self.extract_proposal_from_v1(response)?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(self.extract_proposal_from_v2(response.body().to_vec())?)),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<(Vec<u8>, ohttp::ClientResponse), OhttpEncapsulationError> {
        let fallback_target = self.pj_url();
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    // FIXME: could be &str
    fn extract_proposal_from_v1(&mut self, response: String) -> Result<UncheckedProposal, Error> {
        Ok(self.unchecked_from_payload(response)?)
    }

    // FIXME: could be &[u8] because we've got a known length
    fn extract_proposal_from_v2(&mut self, response: Vec<u8>) -> Result<UncheckedProposal, Error> {
        let (payload_bytes, e) = decrypt_message_a(&response, self.context.s.secret_key().clone())?;
        self.context.e = Some(e);
        let payload = String::from_utf8(payload_bytes).map_err(InternalRequestError::Utf8)?;
        Ok(self.unchecked_from_payload(payload)?)
    }

    fn unchecked_from_payload(
        &mut self,
        payload: String, // FIXME: could be &str
    ) -> Result<UncheckedProposal, RequestError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {}, base64: {}", query, base64); // my guess is no \n so default is wrong
        let unchecked_psbt = Psbt::from_str(base64).map_err(InternalRequestError::ParsePsbt)?;
        let psbt = unchecked_psbt.validate().map_err(InternalRequestError::InconsistentPsbt)?;
        log::debug!("Received original psbt: {:?}", psbt);
        let mut params = Params::from_query_pairs(url::form_urlencoded::parse(query.as_bytes()))
            .map_err(InternalRequestError::SenderParams)?;

        // Output substitution must be disabled for V1 sessions in V2 contexts.
        //
        // V2 contexts depend on a payjoin directory to store and forward payjoin
        // proposals. Plaintext V1 proposals are vulnerable to output replacement
        // attacks by a malicious directory if output substitution is not disabled.
        // V2 proposals are authenticated and encrypted to prevent such attacks.
        //
        // see: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server
        if params.v == 1 {
            params.disable_output_substitution = true;
        }

        log::debug!("Received request with params: {:?}", params);
        let inner = super::UncheckedProposal { psbt, params };
        Ok(UncheckedProposal { inner, context: self.context.clone() })
    }

    pub fn pj_uri_builder(&self) -> PjUriBuilder {
        PjUriBuilder::new(
            self.context.address.clone(),
            self.pj_url(),
            Some(self.context.s.public_key().clone()),
            Some(self.context.ohttp_keys.clone()),
            Some(self.context.expiry),
        )
    }

    // The contents of the `&pj=` query parameter.
    // This identifies a session at the payjoin directory server.
    pub fn pj_url(&self) -> Url {
        let id_base64 = BASE64_URL_SAFE_NO_PAD.encode(self.id());
        let mut url = self.context.directory.clone();
        {
            let mut path_segments =
                url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
            path_segments.push(&id_base64);
        }
        url
    }

    /// The per-session identifier
    pub fn id(&self) -> [u8; 8] {
        let hash = sha256::Hash::hash(&self.context.s.public_key().to_compressed_bytes());
        hash.as_byte_array()[..8]
            .try_into()
            .expect("truncating SHA256 to 8 bytes should always succeed")
    }
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to process the request. It is returned by
/// [`UncheckedProposal::from_request()`](super::::UncheckedProposal::from_request()).
///
/// If you are implementing an interactive payment processor, you should get extract the original
/// transaction with extract_tx_to_schedule_broadcast() and schedule, followed by checking
/// that the transaction can be broadcast with check_broadcast_suitability. Otherwise it is safe to
/// call assume_interactive_receive to proceed with validation.
#[derive(Debug, Clone)]
pub struct UncheckedProposal {
    inner: super::UncheckedProposal,
    context: SessionContext,
}

impl UncheckedProposal {
    /// The Sender's Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.inner.extract_tx_to_schedule_broadcast()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `extract_tx_to_sheculed_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, Error>,
    ) -> Result<MaybeInputsOwned, Error> {
        let inner = self.inner.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(MaybeInputsOwned { inner, context: self.context })
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        let inner = self.inner.assume_interactive_receiver();
        MaybeInputsOwned { inner, context: self.context }
    }
}

/// Typestate to validate that the Original PSBT has no receiver-owned inputs.
///
/// Call [`check_no_receiver_owned_inputs()`](struct.UncheckedProposal.html#method.check_no_receiver_owned_inputs) to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    inner: super::MaybeInputsOwned,
    context: SessionContext,
}

impl MaybeInputsOwned {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<MaybeInputsSeen, Error> {
        let inner = self.inner.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { inner, context: self.context })
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`check_no_inputs_seen`](struct.MaybeInputsSeen.html#method.check_no_inputs_seen_before) to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    inner: super::MaybeInputsSeen,
    context: SessionContext,
}

impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, Error>,
    ) -> Result<OutputsUnknown, Error> {
        let inner = self.inner.check_no_inputs_seen_before(is_known)?;
        Ok(OutputsUnknown { inner, context: self.context })
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    inner: super::OutputsUnknown,
    context: SessionContext,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<WantsOutputs, Error> {
        let inner = self.inner.identify_receiver_outputs(is_receiver_output)?;
        Ok(WantsOutputs { inner, context: self.context })
    }
}

/// A checked proposal that the receiver may substitute or add outputs to
#[derive(Debug, Clone)]
pub struct WantsOutputs {
    inner: super::WantsOutputs,
    context: SessionContext,
}

impl WantsOutputs {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.inner.is_output_substitution_disabled()
    }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.inner.substitute_receiver_script(output_script)?;
        Ok(Self { inner, context: self.context })
    }

    /// Replace **all** receiver outputs with one or more provided outputs.
    /// The drain script specifies which address to *drain* coins to. An output corresponding to
    /// that address must be included in `replacement_outputs`. The value of that output may be
    /// increased or decreased depending on the receiver's input contributions and whether the
    /// receiver needs to pay for additional miner fees (e.g. in the case of adding many outputs).
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: Vec<TxOut>, // FIXME could be Iterator<Item = &TxOut>
        drain_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.inner.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Self { inner, context: self.context })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> WantsInputs {
        let inner = self.inner.commit_outputs();
        WantsInputs { inner, context: self.context }
    }
}

/// A checked proposal that the receiver may contribute inputs to to make a payjoin
#[derive(Debug, Clone)]
pub struct WantsInputs {
    inner: super::WantsInputs,
    context: SessionContext,
}

impl WantsInputs {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    /// if min(in) > min(out) then UIH1 else UIH2
    /// https://eprint.iacr.org/2022/589.pdf
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = &InputPair>, // FIXME &InputPair & clone out
    ) -> Result<InputPair, SelectionError> {
        self.inner.try_preserving_privacy(candidate_inputs)
    }

    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>, // Own and place in payjoin_psbt
    ) -> Result<WantsInputs, InputContributionError> {
        let inner = self.inner.contribute_inputs(inputs)?;
        Ok(WantsInputs { inner, context: self.context })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> ProvisionalProposal {
        let inner = self.inner.commit_inputs();
        ProvisionalProposal { inner, context: self.context }
    }
}

/// A checked proposal that the receiver may sign and finalize to make a proposal PSBT that the
/// sender will accept.
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    inner: super::ProvisionalProposal,
    context: SessionContext,
}

impl ProvisionalProposal {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, Error>,
        min_feerate_sat_per_vb: Option<FeeRate>,
        max_feerate_sat_per_vb: FeeRate,
    ) -> Result<PayjoinProposal, Error> {
        let inner = self.inner.finalize_proposal(
            wallet_process_psbt,
            min_feerate_sat_per_vb,
            max_feerate_sat_per_vb,
        )?;
        Ok(PayjoinProposal { inner, context: self.context })
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[derive(Clone)]
pub struct PayjoinProposal {
    inner: super::PayjoinProposal,
    context: SessionContext,
}

impl PayjoinProposal {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.inner.is_output_substitution_disabled()
    }

    pub fn psbt(&self) -> &Psbt { self.inner.psbt() }

    pub fn extract_v1_req(&self) -> String { self.inner.payjoin_psbt.to_string() }

    #[cfg(feature = "v2")]
    pub fn extract_v2_req(&mut self) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.inner.payjoin_psbt.serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource =
                self.context.directory.join(&sender_subdir).map_err(|e| Error::Server(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.extract_v1_req().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.context.s.public_key());
            target_resource = self
                .context
                .directory
                .join(&receiver_subdir)
                .map_err(|e| Error::Server(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;
        let url = self.context.ohttp_relay.clone();
        let req = Request::new_v2(url, body);
        Ok((req, ctx))
    }

    #[cfg(feature = "v2")]
    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        res: Vec<u8>, // FIXME could be &[u8]
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        let res = ohttp_decapsulate(ohttp_context, &res)?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(Error::Server(
                format!("Payjoin Post failed, expected Success status, got {}", res.status())
                    .into(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "v2")]
    fn receiver_ser_de_roundtrip() {
        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::K256Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

        let session = Receiver {
            context: SessionContext {
                address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
                    .unwrap()
                    .assume_checked(),
                directory: url::Url::parse("https://directory.com").unwrap(),
                subdirectory: None,
                ohttp_keys: OhttpKeys(
                    ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap(),
                ),
                ohttp_relay: url::Url::parse("https://relay.com").unwrap(),
                expiry: SystemTime::now() + Duration::from_secs(60),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
        };
        let serialized = serde_json::to_string(&session).unwrap();
        let deserialized: Receiver = serde_json::from_str(&serialized).unwrap();
        assert_eq!(session, deserialized);
    }
}
