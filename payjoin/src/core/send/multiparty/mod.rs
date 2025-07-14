use bitcoin::{FeeRate, Psbt};
use error::{
    CreateRequestError, FinalizedError, InternalCreateRequestError, InternalFinalizedError,
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::v2::{self, extract_request, EncapsulationError, HpkeContext};
use super::{serialize_url, AdditionalFeeContribution, BuildSenderError};
use crate::hpke::decrypt_message_b;
use crate::ohttp::{process_get_res, process_post_res};
use crate::output_substitution::OutputSubstitution;
use crate::persist::NoopSessionPersister;
use crate::send::v2::V2PostContext;
use crate::uri::UrlExt;
use crate::{ImplementationError, IntoUrl, PjUri, Request, Version};

mod error;

#[derive(Clone)]
pub struct SenderBuilder<'a>(v2::SenderBuilder<'a>);

impl<'a> SenderBuilder<'a> {
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self { Self(v2::SenderBuilder::new(psbt, uri)) }

    pub fn build_recommended(self, min_fee_rate: FeeRate) -> Result<Sender, BuildSenderError> {
        let noop_persister = NoopSessionPersister::default();
        let sender = self
            .0
            .build_recommended(min_fee_rate)
            .save(&noop_persister)
            .expect("Noop persister should never fail");
        Ok(Sender(sender))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender(v2::Sender<v2::WithReplyKey>);

impl Sender {
    /// Important: This request must not be retried or reused on failure.
    /// Retransmitting the same ciphertext breaks OHTTP privacy properties.
    /// The specific concern is that the relay can see that a request is being retried,
    /// which leaks that it's all the same request.
    pub fn create_v2_post_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, PostContext), CreateRequestError> {
        let rs = self
            .0
            .extract_rs_pubkey()
            .map_err(InternalCreateRequestError::ParseReceiverPubkeyParam)?;
        let mut ohttp_keys = self
            .0
            .endpoint()
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let body = serialize_v2_body(
            &self.0.v1.psbt_ctx.original_psbt,
            self.0.v1.psbt_ctx.output_substitution,
            self.0.v1.psbt_ctx.fee_contribution,
            self.0.v1.psbt_ctx.min_fee_rate,
        )?;
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            self.0.reply_key.clone(),
            body,
            self.0.endpoint().clone(),
            rs.clone(),
            &mut ohttp_keys,
        )
        .map_err(InternalCreateRequestError::V2CreateRequest)?;
        let v2_post_ctx = V2PostContext {
            endpoint: self.0.endpoint().clone(),
            psbt_ctx: self.0.v1.psbt_ctx.clone(),
            hpke_ctx: HpkeContext::new(rs, &self.0.reply_key),
            ohttp_ctx,
        };
        Ok((request, PostContext(v2_post_ctx)))
    }

    pub fn process_response(
        self,
        response: &[u8],
        post_ctx: PostContext,
    ) -> Result<GetContext, EncapsulationError> {
        let noop_persister = NoopSessionPersister::default();
        let res = self
            .0
            .process_response(response, post_ctx.0)
            .save(&noop_persister)
            .map_err(|e| e.api_error().expect("Noop persister should never fail, if `save` fails its due to a API related error"))?;
        Ok(GetContext(res))
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
        Version::Two,
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
pub struct GetContext(v2::Sender<v2::V2GetContext>);

impl GetContext {
    /// Construct the GET request that will give us the psbt to be finalized
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), crate::send::v2::CreateRequestError> {
        self.0.create_poll_request(ohttp_relay)
    }

    /// Process the response from the directory. Provide a closure to finalize the inputs
    /// you own. With the FinalizeContext, you can extract the last POST request and process the response sent back from the directory.
    pub fn process_response_and_finalize(
        &self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
        finalize_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> Result<FinalizeContext, FinalizedError> {
        let psbt_ctx = self.0.psbt_ctx.clone();
        let body = match process_get_res(response, ohttp_ctx)? {
            Some(body) => body,
            None => return Err(FinalizedError::from(InternalFinalizedError::MissingResponse)),
        };
        let psbt = decrypt_message_b(
            &body,
            self.0.hpke_ctx.receiver.clone(),
            self.0.hpke_ctx.reply_pair.secret_key().clone(),
        )
        .map_err(InternalFinalizedError::Hpke)?;

        let proposal = Psbt::deserialize(&psbt).map_err(InternalFinalizedError::Psbt)?;
        let psbt =
            process_proposal(psbt_ctx, proposal).map_err(InternalFinalizedError::Proposal)?;
        let finalized_psbt = finalize_psbt(&psbt).map_err(InternalFinalizedError::FinalizePsbt)?;
        Ok(FinalizeContext {
            hpke_ctx: self.0.hpke_ctx.clone(),
            directory_url: self.0.endpoint.clone(),
            psbt: finalized_psbt,
        })
    }
}

/// Finalize context is used to extract the last POST request and process the response sent back from the directory.
pub struct FinalizeContext {
    hpke_ctx: HpkeContext,
    directory_url: Url,
    psbt: Psbt,
}

impl FinalizeContext {
    pub fn extract_req(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        let reply_key = self.hpke_ctx.reply_pair.secret_key();
        let body = serialize_v2_body(
            &self.psbt,
            OutputSubstitution::Disabled,
            None,
            FeeRate::BROADCAST_MIN,
        )?;
        let mut ohttp_keys = self
            .directory_url
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            reply_key.clone(),
            body,
            self.directory_url.clone(),
            self.hpke_ctx.receiver.clone(),
            &mut ohttp_keys,
        )
        .map_err(InternalCreateRequestError::V2CreateRequest)?;
        Ok((request, ohttp_ctx))
    }

    pub fn process_response(
        self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> Result<(), FinalizedError> {
        match process_post_res(response, ohttp_ctx) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// The same as `crate::send::PsbtContext::process_proposal` but without checking receiver input finalization
fn process_proposal(
    psbt_ctx: crate::send::PsbtContext,
    mut proposal: Psbt,
) -> crate::send::InternalResult<Psbt> {
    psbt_ctx.basic_checks(&proposal)?;
    psbt_ctx.check_inputs(&proposal, false)?;
    let contributed_fee = psbt_ctx.check_outputs(&proposal)?;
    psbt_ctx.restore_original_utxos(&mut proposal)?;
    psbt_ctx.check_fees(&proposal, contributed_fee)?;
    Ok(proposal)
}

fn append_optimisitic_merge_query_param(url: &mut Url) {
    url.query_pairs_mut().append_pair("optimisticmerge", "true");
}

#[cfg(test)]
mod test {
    use bitcoin::FeeRate;
    use payjoin_test_utils::BoxError;
    use url::Url;

    use super::*;
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
            Version::Two,
        );
        append_optimisitic_merge_query_param(&mut url);
        assert_eq!(url, Url::parse("http://localhost?v=2&optimisticmerge=true")?);

        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
            Version::Two,
        );
        assert_eq!(url, Url::parse("http://localhost?v=2")?);

        Ok(())
    }
}
