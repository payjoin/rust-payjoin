use bitcoin::{FeeRate, Psbt};
use error::{
    CreateRequestError, FinalizeResponseError, FinalizedError, InternalCreateRequestError,
    InternalFinalizeResponseError, InternalFinalizedError,
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::v2::{self, extract_request, EncapsulationError, HpkeContext};
use super::{serialize_url, AdditionalFeeContribution, BuildSenderError, InternalResult};
use crate::hpke::decrypt_message_b;
use crate::ohttp::ohttp_decapsulate;
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    MaybeBadInitInputsTransition, MaybeFatalTransition, MaybeFatalTransitionWithNoResults,
    MaybeSuccessTransition, NoopPersister,
};
use crate::send::v2::V2PostContext;
use crate::uri::UrlExt;
use crate::{ImplementationError, IntoUrl, PjUri, Request};

pub use session::SenderSessionEvent;

mod error;
pub(crate) mod session;

#[derive(Clone)]
pub struct SenderBuilder<'a>(v2::SenderBuilder<'a>);

impl<'a> SenderBuilder<'a> {
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self { Self(v2::SenderBuilder::new(psbt, uri)) }

    pub fn build_recommended(
        self,
        min_fee_rate: FeeRate,
    ) -> MaybeBadInitInputsTransition<
        SenderSessionEvent,
        Sender<SenderWithReplyKey>,
        BuildSenderError,
    > {
        let noop_persister = NoopPersister::<crate::send::v2::SenderSessionEvent>::default();
        let sender = self
            .0
            .build_recommended(min_fee_rate)
            .save(&noop_persister)
            .expect("Noop does not fail");

        let sender_with_reply_key = SenderWithReplyKey(sender);
        let next_state = Sender { state: sender_with_reply_key.clone() };
        MaybeBadInitInputsTransition::success(
            SenderSessionEvent::CreatedReplyKey(sender_with_reply_key),
            next_state,
        )
    }
}

#[derive(Clone)]
pub struct Sender<State> {
    state: State,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SenderWithReplyKey(pub(crate) v2::Sender<v2::SenderWithReplyKey>);

impl Sender<SenderWithReplyKey> {
    pub fn extract_v2(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, PostContext), CreateRequestError> {
        let rs = self
            .state
            .0
            .extract_rs_pubkey()
            .map_err(InternalCreateRequestError::ParseReceiverPubkeyParam)?;
        let mut ohttp_keys = self
            .state
            .0
            .endpoint()
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let inner = self.state.0.state();
        let body = serialize_v2_body(
            &inner.v1.psbt,
            inner.v1.output_substitution,
            inner.v1.fee_contribution,
            inner.v1.min_fee_rate,
        )?;
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            inner.reply_key.clone(),
            body,
            self.state.0.endpoint().clone(),
            rs.clone(),
            &mut ohttp_keys,
        )
        .map_err(InternalCreateRequestError::V2CreateRequest)?;
        let v2_post_ctx = V2PostContext {
            endpoint: self.state.0.endpoint().clone(),
            psbt_ctx: crate::send::PsbtContext {
                original_psbt: inner.v1.psbt.clone(),
                output_substitution: inner.v1.output_substitution,
                fee_contribution: inner.v1.fee_contribution,
                payee: inner.v1.payee.clone(),
                min_fee_rate: inner.v1.min_fee_rate,
            },
            hpke_ctx: HpkeContext::new(rs, &inner.reply_key),
            ohttp_ctx,
        };
        Ok((request, PostContext(v2_post_ctx)))
    }

    pub fn process_response(
        self,
        response: &[u8],
        post_ctx: PostContext,
    ) -> MaybeFatalTransition<SenderSessionEvent, Sender<GetContext>, EncapsulationError> {
        let noop_persister = NoopPersister::<crate::send::v2::SenderSessionEvent>::default();
        let res = self
            .state
            .0
            .process_response(response, post_ctx.0)
            .save(&noop_persister)
            .expect("Noop does not fail");

        let next_state = Sender { state: GetContext(res.clone()) };
        MaybeFatalTransition::success(SenderSessionEvent::V2GetContext(GetContext(res)), next_state)
    }
}

fn serialize_v2_body(
    psbt: &Psbt,
    output_substitution: OutputSubstitution,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
) -> Result<Vec<u8>, CreateRequestError> {
    let mut url = serialize_url(
        Url::parse("http://localhost").unwrap(),
        output_substitution,
        fee_contribution,
        min_fee_rate,
        "2",
    );
    append_optimisitic_merge_query_param(&mut url);
    let base64 = psbt.to_string();
    Ok(format!("{}\n{}", base64, url.query().unwrap_or_default()).into_bytes())
}

/// Post context is used to process the response from the directory and generate
/// the GET context which can be used to extract a request for the receiver
pub struct PostContext(v2::V2PostContext);

/// Get context is used to extract a request for the receiver. In the multiparty context this is a
/// merged PSBT with other senders.
#[derive(Clone, Serialize, Deserialize)]
pub struct GetContext(pub v2::Sender<v2::V2GetContext>);

impl Sender<GetContext> {
    /// Extract the GET request that will give us the psbt to be finalized
    pub fn extract_req(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), crate::send::v2::CreateRequestError> {
        self.state.0.extract_req(ohttp_relay)
    }

    /// Process the response from the directory. Provide a closure to finalize the inputs
    /// you own. With the FinalizeContext, you can extract the last POST request and process the response sent back from the directory.
    pub fn process_response_and_finalize(
        &self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
        finalize_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> MaybeFatalTransitionWithNoResults<
        SenderSessionEvent,
        Sender<FinalizeContext>,
        Sender<GetContext>,
        FinalizedError,
    > {
        let state = self.state.0.state();
        let psbt_ctx = PsbtContext { inner: state.psbt_ctx.clone() };

        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] = match response
            .try_into()
        {
            Ok(response_array) => response_array,
            Err(_) =>
                return MaybeFatalTransitionWithNoResults::fatal(
                    SenderSessionEvent::SessionInvalid(format!("Invalid size: {}", response.len())),
                    InternalFinalizedError::InvalidSize.into(),
                ),
        };

        let response = match ohttp_decapsulate(ohttp_ctx, response_array) {
            Ok(response) => response,
            Err(e) =>
                return MaybeFatalTransitionWithNoResults::transient(
                    InternalFinalizedError::Ohttp(e).into(),
                ),
        };
        let body = match response.status() {
            http::StatusCode::OK => Some(response.body().to_vec()),
            http::StatusCode::ACCEPTED => None,
            _ =>
                return MaybeFatalTransitionWithNoResults::transient(
                    InternalFinalizedError::UnexpectedStatusCode(response.status()).into(),
                ),
        };
        if let Some(body) = body {
            let psbt = match decrypt_message_b(
                &body,
                state.hpke_ctx.receiver.clone(),
                state.hpke_ctx.reply_pair.secret_key().clone(),
            ) {
                Ok(psbt) => psbt,
                Err(e) =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        SenderSessionEvent::SessionInvalid(format!("Hpke error: {}", e)),
                        InternalFinalizedError::Hpke(e).into(),
                    ),
            };

            let proposal = match Psbt::deserialize(&psbt) {
                Ok(proposal) => proposal,
                Err(e) =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        SenderSessionEvent::SessionInvalid(format!(
                            "Psbt deserialize error: {}",
                            e
                        )),
                        InternalFinalizedError::Psbt(e).into(),
                    ),
            };

            let psbt = match psbt_ctx.process_proposal(proposal) {
                Ok(psbt) => psbt,
                Err(e) =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        SenderSessionEvent::SessionInvalid(format!("Proposal error: {}", e)),
                        InternalFinalizedError::Proposal(e).into(),
                    ),
            };
            let finalized_psbt = match finalize_psbt(&psbt) {
                Ok(finalized_psbt) => finalized_psbt,
                Err(e) =>
                    return MaybeFatalTransitionWithNoResults::transient(
                        InternalFinalizedError::FinalizePsbt(e).into(),
                    ),
            };
            let next_state = FinalizeContext {
                hpke_ctx: state.hpke_ctx.clone(),
                directory_url: state.endpoint.clone(),
                psbt: finalized_psbt,
            };
            MaybeFatalTransitionWithNoResults::success(
                SenderSessionEvent::FinalizeContext(next_state.clone()),
                Sender { state: next_state },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(self.clone())
        }
    }
}

/// Finalize context is used to extract the last POST request and process the response sent back from the directory.
#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizeContext {
    hpke_ctx: HpkeContext,
    directory_url: Url,
    psbt: Psbt,
}

impl Sender<FinalizeContext> {
    pub fn extract_req(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        let reply_key = self.state.hpke_ctx.reply_pair.secret_key();
        let body = serialize_v2_body(
            &self.state.psbt,
            OutputSubstitution::Disabled,
            None,
            FeeRate::BROADCAST_MIN,
        )?;
        let mut ohttp_keys = self
            .state
            .directory_url
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            reply_key.clone(),
            body,
            self.state.directory_url.clone(),
            self.state.hpke_ctx.receiver.clone(),
            &mut ohttp_keys,
        )
        .map_err(InternalCreateRequestError::V2CreateRequest)?;
        Ok((request, ohttp_ctx))
    }

    pub fn process_response(
        self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> MaybeSuccessTransition<(), FinalizeResponseError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            match response.try_into() {
                Ok(response_array) => response_array,
                Err(_) =>
                    return MaybeSuccessTransition::transient(
                        InternalFinalizeResponseError::InvalidSize(response.len()).into(),
                    ),
            };

        let response = match ohttp_decapsulate(ohttp_ctx, response_array) {
            Ok(response) => response,
            Err(e) =>
                return MaybeSuccessTransition::transient(
                    InternalFinalizeResponseError::Ohttp(e).into(),
                ),
        };
        match response.status() {
            http::StatusCode::OK | http::StatusCode::ACCEPTED => MaybeSuccessTransition::success(()),
            _ => MaybeSuccessTransition::transient(
                InternalFinalizeResponseError::UnexpectedStatusCode(response.status()).into(),
            ),
        }
    }
}

pub(crate) struct PsbtContext {
    inner: crate::send::PsbtContext,
}

impl PsbtContext {
    fn process_proposal(self, mut proposal: Psbt) -> InternalResult<Psbt> {
        // TODO(armins) add multiparty check fees modeled after crate::send::PsbtContext::check_fees
        // The problem with this is that some of the inputs will be missing witness_utxo or non_witness_utxo field in the psbt so the default psbt.fee() will fail
        // Similarly we need to implement a check for the inputs. It would be useful to have all the checks as crate::send::PsbtContext::check_inputs
        // However that method expects the receiver to have provided witness for their inputs. In a ns1r the receiver will not sign any inputs of the optimistic merged psbt
        self.inner.basic_checks(&proposal)?;
        self.inner.check_outputs(&proposal)?;
        self.inner.restore_original_utxos(&mut proposal)?;
        Ok(proposal)
    }
}

fn append_optimisitic_merge_query_param(url: &mut Url) {
    url.query_pairs_mut().append_pair("optimisticmerge", "true");
}

#[cfg(test)]
mod test {
    use bitcoin::FeeRate;
    use payjoin_test_utils::BoxError;
    use url::Url;

    use crate::output_substitution::OutputSubstitution;
    use crate::send::multiparty::append_optimisitic_merge_query_param;
    use crate::send::serialize_url;

    #[test]
    fn test_optimistic_merge_query_param() -> Result<(), BoxError> {
        let mut url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
            "2",
        );
        append_optimisitic_merge_query_param(&mut url);
        assert_eq!(url, Url::parse("http://localhost?v=2&optimisticmerge=true")?);

        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
            "2",
        );
        assert_eq!(url, Url::parse("http://localhost?v=2")?);

        Ok(())
    }
}
