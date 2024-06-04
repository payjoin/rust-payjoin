use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{rand, PublicKey};
use bitcoin::{base64, Amount, FeeRate, OutPoint, Script, TxOut};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use url::Url;

use super::{Error, InternalRequestError, RequestError, SelectionError};
use crate::psbt::PsbtExt;
use crate::receive::optional_parameters::Params;
use crate::{OhttpKeys, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionContext {
    directory: url::Url,
    ohttp_keys: OhttpKeys,
    ohttp_relay: url::Url,
    s: bitcoin::secp256k1::KeyPair,
    e: Option<bitcoin::secp256k1::PublicKey>,
}

#[derive(Debug, Clone)]
pub struct SessionInitializer {
    context: SessionContext,
}

#[cfg(feature = "v2")]
impl SessionInitializer {
    pub fn from_directory_config(directory: Url, ohttp_keys: OhttpKeys, ohttp_relay: Url) -> Self {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);
        Self {
            context: SessionContext {
                directory,
                ohttp_keys,
                ohttp_relay,
                s: bitcoin::secp256k1::KeyPair::from_secret_key(&secp, &sk),
                e: None,
            },
        }
    }

    pub fn extract_req(&mut self) -> Result<(Request, ohttp::ClientResponse), Error> {
        let url = self.context.ohttp_relay.clone();
        let subdirectory = subdir_path_from_pubkey(&self.context.s.public_key());
        let (body, ctx) = crate::v2::ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "POST",
            self.context.directory.as_str(),
            Some(subdirectory.as_bytes()),
        )?;
        let req = Request { url, body };
        Ok((req, ctx))
    }

    pub fn process_res(
        self,
        mut res: impl std::io::Read,
        ctx: ohttp::ClientResponse,
    ) -> Result<ActiveSession, Error> {
        // TODO decapsulate enroll response, for now it does no auth or nothing
        let mut buf = Vec::new();
        let _ = res.read_to_end(&mut buf);
        let response = crate::v2::ohttp_decapsulate(ctx, &buf)?;
        if !response.status().is_success() {
            return Err(Error::Server(
                format!("Enrollment failed, expected success status",).into(),
            ));
        }

        Ok(ActiveSession { context: self.context.clone() })
    }
}

fn subdir_path_from_pubkey(pubkey: &bitcoin::secp256k1::PublicKey) -> String {
    let pubkey = pubkey.serialize();
    let b64_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    base64::encode_config(pubkey, b64_config)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSession {
    context: SessionContext,
}

impl ActiveSession {
    pub fn extract_req(&mut self) -> Result<(Request, ohttp::ClientResponse), Error> {
        let (body, ohttp_ctx) = self.fallback_req_body()?;
        let url = self.context.ohttp_relay.clone();
        let req = Request { url, body };
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        mut body: impl std::io::Read,
        context: ohttp::ClientResponse,
    ) -> Result<Option<UncheckedProposal>, Error> {
        let mut buf = Vec::new();
        let _ = body.read_to_end(&mut buf);
        log::trace!("decapsulating directory response");
        let response = crate::v2::ohttp_decapsulate(context, &buf)?;
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

    fn fallback_req_body(&mut self) -> Result<(Vec<u8>, ohttp::ClientResponse), Error> {
        let fallback_target = format!("{}{}", &self.context.directory, self.fallback_target());
        log::trace!("Fallback request target: {}", fallback_target.as_str());
        let fallback_target = self.fallback_target();
        Ok(crate::v2::ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "GET",
            &fallback_target,
            None,
        )?)
    }

    fn extract_proposal_from_v1(&mut self, response: String) -> Result<UncheckedProposal, Error> {
        Ok(self.unchecked_from_payload(response)?)
    }

    fn extract_proposal_from_v2(&mut self, response: Vec<u8>) -> Result<UncheckedProposal, Error> {
        let (payload_bytes, e) =
            crate::v2::decrypt_message_a(&response, self.context.s.secret_key())?;
        self.context.e = Some(e);
        let payload = String::from_utf8(payload_bytes).map_err(InternalRequestError::Utf8)?;
        Ok(self.unchecked_from_payload(payload)?)
    }

    fn unchecked_from_payload(
        &mut self,
        payload: String,
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

    pub fn fallback_target(&self) -> String {
        let pubkey = &self.context.s.public_key().serialize();
        let b64_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let pubkey_base64 = base64::encode_config(pubkey, b64_config);
        format!("{}{}", &self.context.directory, pubkey_base64)
    }

    /// The per-session public key to use as an identifier
    pub fn public_key(&self) -> PublicKey { self.context.s.public_key() }
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
#[derive(Clone)]
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
#[derive(Clone)]
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
    ) -> Result<MaybeMixedInputScripts, Error> {
        let inner = self.inner.check_inputs_not_owned(is_owned)?;
        Ok(MaybeMixedInputScripts { inner, context: self.context })
    }
}

/// Typestate to validate that the Original PSBT has no mixed input types.
///
/// Call [`check_no_mixed_input_types`](struct.UncheckedProposal.html#method.check_no_mixed_input_scripts) to proceed.
#[derive(Clone)]
pub struct MaybeMixedInputScripts {
    inner: super::MaybeMixedInputScripts,
    context: SessionContext,
}

impl MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(self) -> Result<MaybeInputsSeen, RequestError> {
        let inner = self.inner.check_no_mixed_input_scripts()?;
        Ok(MaybeInputsSeen { inner, context: self.context })
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`check_no_inputs_seen`](struct.MaybeInputsSeen.html#method.check_no_inputs_seen_before) to proceed.
#[derive(Clone)]
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
#[derive(Clone)]
pub struct OutputsUnknown {
    inner: super::OutputsUnknown,
    context: SessionContext,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<ProvisionalProposal, Error> {
        let inner = self.inner.identify_receiver_outputs(is_receiver_output)?;
        Ok(ProvisionalProposal { inner, context: self.context })
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    pub inner: super::ProvisionalProposal,
    context: SessionContext,
}

impl ProvisionalProposal {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    // if min(out) < min(in) then UIH1 else UIH2
    // https://eprint.iacr.org/2022/589.pdf
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: HashMap<Amount, OutPoint>,
    ) -> Result<OutPoint, SelectionError> {
        self.inner.try_preserving_privacy(candidate_inputs)
    }

    pub fn contribute_witness_input(&mut self, txo: TxOut, outpoint: OutPoint) {
        self.inner.contribute_witness_input(txo, outpoint)
    }

    pub fn contribute_non_witness_input(&mut self, tx: bitcoin::Transaction, outpoint: OutPoint) {
        self.inner.contribute_non_witness_input(tx, outpoint)
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.inner.is_output_substitution_disabled()
    }

    /// Just replace an output address with
    pub fn substitute_output_address(&mut self, substitute_address: bitcoin::Address) {
        self.inner.substitute_output_address(substitute_address)
    }

    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, Error>,
        min_feerate_sat_per_vb: Option<FeeRate>,
    ) -> Result<PayjoinProposal, Error> {
        let inner = self.inner.finalize_proposal(wallet_process_psbt, min_feerate_sat_per_vb)?;
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
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.inner.utxos_to_be_locked()
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.inner.is_output_substitution_disabled()
    }

    pub fn owned_vouts(&self) -> &Vec<usize> { self.inner.owned_vouts() }

    pub fn psbt(&self) -> &Psbt { self.inner.psbt() }

    pub fn extract_v1_req(&self) -> String { base64::encode(self.inner.payjoin_psbt.serialize()) }

    #[cfg(feature = "v2")]
    pub fn extract_v2_req(&mut self) -> Result<(Request, ohttp::ClientResponse), Error> {
        let body = match self.context.e {
            Some(e) => {
                let mut payjoin_bytes = self.inner.payjoin_psbt.serialize();
                log::debug!("THERE IS AN e: {}", e);
                crate::v2::encrypt_message_b(&mut payjoin_bytes, e)
            }
            None => Ok(self.extract_v1_req().as_bytes().to_vec()),
        }?;
        let post_payjoin_target = format!(
            "{}{}/payjoin",
            self.context.directory.as_str(),
            subdir_path_from_pubkey(&self.context.s.public_key())
        );
        log::debug!("Payjoin post target: {}", post_payjoin_target.as_str());
        let (body, ctx) = crate::v2::ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "POST",
            &post_payjoin_target,
            Some(&body),
        )?;
        let url = self.context.ohttp_relay.clone();
        let req = Request { url, body };
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
        res: Vec<u8>,
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        let res = crate::v2::ohttp_decapsulate(ohttp_context, &res)?;
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
impl Serialize for SessionContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SessionContext", 4)?;
        state.serialize_field("directory", &self.directory)?;
        state.serialize_field("ohttp_keys", &self.ohttp_keys)?;
        state.serialize_field("ohttp_relay", &self.ohttp_relay)?;
        state.serialize_field("s", &self.s)?;
        state.serialize_field("e", &self.e)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for SessionContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Directory,
            OhttpKeys,
            OhttpRelay,
            S,
            E,
        }

        struct SessionContextVisitor;

        impl<'de> Visitor<'de> for SessionContextVisitor {
            type Value = SessionContext;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ActiveSession")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SessionContext, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut directory = None;
                let mut ohttp_keys = None;
                let mut ohttp_relay = None;
                let mut s = None;
                let mut e = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Directory => {
                            if directory.is_some() {
                                return Err(de::Error::duplicate_field("directory"));
                            }
                            directory = Some(map.next_value()?);
                        }
                        Field::OhttpKeys => {
                            if ohttp_keys.is_some() {
                                return Err(de::Error::duplicate_field("ohttp_keys"));
                            }
                            ohttp_keys = Some(map.next_value()?);
                        }
                        Field::OhttpRelay => {
                            if ohttp_relay.is_some() {
                                return Err(de::Error::duplicate_field("ohttp_relay"));
                            }
                            ohttp_relay = Some(map.next_value()?);
                        }
                        Field::S => {
                            if s.is_some() {
                                return Err(de::Error::duplicate_field("s"));
                            }
                            s = Some(map.next_value()?);
                        }
                        Field::E => {
                            if e.is_some() {
                                return Err(de::Error::duplicate_field("e"));
                            }
                            e = Some(map.next_value()?);
                        }
                    }
                }
                let directory = directory.ok_or_else(|| de::Error::missing_field("directory"))?;
                let ohttp_keys =
                    ohttp_keys.ok_or_else(|| de::Error::missing_field("ohttp_keys"))?;
                let ohttp_relay =
                    ohttp_relay.ok_or_else(|| de::Error::missing_field("ohttp_relay"))?;
                let s = s.ok_or_else(|| de::Error::missing_field("s"))?;
                let e = e.ok_or_else(|| de::Error::missing_field("e"))?;
                Ok(SessionContext { directory, ohttp_keys, ohttp_relay, s, e })
            }
        }

        const FIELDS: &[&str] = &["directory", "ohttp_keys", "ohttp_relay", "s", "e"];
        deserializer.deserialize_struct("SessionContext", FIELDS, SessionContextVisitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "v2")]
    fn active_session_ser_de_roundtrip() {
        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::X25519Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

        let session = ActiveSession {
            context: SessionContext {
                directory: url::Url::parse("https://directory.com").unwrap(),
                ohttp_keys: OhttpKeys(
                    ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap(),
                ),
                ohttp_relay: url::Url::parse("https://relay.com").unwrap(),
                s: bitcoin::secp256k1::KeyPair::from_secret_key(
                    &bitcoin::secp256k1::Secp256k1::new(),
                    &bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
                ),
                e: None,
            },
        };
        let serialized = serde_json::to_string(&session).unwrap();
        let deserialized: ActiveSession = serde_json::from_str(&serialized).unwrap();
        assert_eq!(session, deserialized);
    }
}
