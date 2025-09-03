use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::receive::v1::{PayjoinProposal, UncheckedOriginalPayload};
use payjoin::receive::Error;
use payjoin::send::v1::SenderBuilder;
use payjoin::{ImplementationError, IntoUrl, Uri, UriExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
use crate::app::{handle_interrupt, http_agent};
use crate::db::Database;

struct Headers<'a>(&'a hyper::HeaderMap);
impl payjoin::receive::v1::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|v| v.to_str()).transpose().ok().flatten()
    }
}

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    async fn new(config: Config) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx };
        app.wallet()
            .network()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn wallet(&self) -> BitcoindWallet { self.wallet.clone() }

    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        let uri =
            Uri::try_from(bip21).map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;
        let uri = uri.assume_checked();
        let uri = uri.check_pj_supported().map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;
        let psbt = self.create_original_psbt(&uri.address, amount, fee_rate)?;
        let (req, ctx) = SenderBuilder::new(psbt, uri.clone())
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?
            .create_v1_post_request();
        let http = http_agent(&self.config)?;
        let body = String::from_utf8(req.body.clone()).unwrap();
        println!("Sending fallback request to {}", &req.url);
        let response = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(body.clone())
            .send()
            .await
            .with_context(|| "HTTP request failed")?;
        let fallback_tx = Psbt::from_str(&body)
            .map_err(|e| anyhow!("Failed to load PSBT from base64: {}", e))?
            .extract_tx()?;
        println!("Sent fallback transaction txid: {}", fallback_tx.compute_txid());
        println!(
            "Sent fallback transaction hex: {:#}",
            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
        );
        let psbt = ctx.process_response(&response.bytes().await?).map_err(|e| {
            tracing::debug!("Error processing response: {e:?}");
            anyhow!("Failed to process response {e}")
        })?;

        self.process_pj_response(psbt)?;
        Ok(())
    }

    #[allow(clippy::incompatible_msrv)]
    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.start_http_server(amount) => { res?; }
            _ = interrupt.changed() => {
                println!("Interrupted.");
            }
        }
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn resume_payjoins(&self) -> Result<()> {
        unimplemented!("resume_payjoins not implemented for v1");
    }

    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()> {
        unimplemented!("history not implemented for v1");
    }
}

impl App {
    fn construct_payjoin_uri(&self, amount: Amount, endpoint: impl IntoUrl) -> Result<String> {
        let pj_receiver_address = self.wallet.get_new_address()?;

        let mut pj_uri = payjoin::receive::v1::build_v1_pj_uri(
            &pj_receiver_address,
            endpoint,
            payjoin::OutputSubstitution::Enabled,
        )?;
        pj_uri.amount = Some(amount);

        Ok(pj_uri.to_string())
    }

    async fn start_http_server(&self, amount: Amount) -> Result<()> {
        let port = self.config.v1()?.port;
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = TcpListener::bind(addr).await?;

        let mut endpoint = self.config.v1()?.pj_endpoint.clone();

        // If --port 0 is specified, a free port is chosen, so we need to set it
        // on the endpoint which must not have a port.
        if port == 0 {
            endpoint
                .set_port(Some(listener.local_addr()?.port()))
                .expect("setting port must succeed");
        }

        let pj_uri_string = self.construct_payjoin_uri(amount, endpoint.as_str())?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            listener.local_addr()?
        );
        println!("{pj_uri_string}");

        let app = self.clone();

        #[cfg(feature = "_manual-tls")]
        let tls_acceptor = self.init_tls_acceptor()?;
        while let Ok((stream, _)) = listener.accept().await {
            let app = app.clone();
            #[cfg(feature = "_manual-tls")]
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                #[cfg(feature = "_manual-tls")]
                let stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        tracing::error!("TLS accept error: {e}");
                        return;
                    }
                };

                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| app.clone().handle_web_request(req)),
                    )
                    .await;
            });
        }
        Ok(())
    }

    #[cfg(feature = "_manual-tls")]
    fn init_tls_acceptor(&self) -> Result<tokio_rustls::TlsAcceptor> {
        use std::sync::Arc;

        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::TlsAcceptor;

        let key_der = std::fs::read(
            self.config
                .certificate_key
                .as_ref()
                .expect("certificate key is required if listening with tls"),
        )?;
        let key = PrivateKeyDer::try_from(key_der.clone())
            .map_err(|e| anyhow::anyhow!("Could not parse key: {}", e))?;

        let cert_der = std::fs::read(
            self.config
                .root_certificate
                .as_ref()
                .expect("certificate key is required if listening with tls"),
        )?;
        let certs = vec![CertificateDer::from(cert_der)];

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;

        server_config.alpn_protocols =
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    async fn handle_web_request(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        tracing::debug!("Received request: {req:?}");
        let mut response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/bip21") => {
                let query_string = req.uri().query().unwrap_or("");
                tracing::debug!("{:?}, {query_string:?}", req.method());
                let query_params: HashMap<_, _> =
                    url::form_urlencoded::parse(query_string.as_bytes()).into_owned().collect();
                let amount = query_params.get("amount").map(|amt| {
                    Amount::from_btc(amt.parse().expect("Failed to parse amount")).unwrap()
                });
                self.handle_get_bip21(amount)
                    .map_err(|e| {
                        tracing::error!("Error handling request: {e}");
                        Response::builder().status(500).body(full(e.to_string())).unwrap()
                    })
                    .unwrap_or_else(|err_resp| err_resp)
            }
            (&Method::POST, _) => self
                .handle_payjoin_post(req)
                .await
                .map_err(|e| {
                    let json = payjoin::receive::JsonReply::from(&e);
                    tracing::error!("Error handling request: {e}");
                    Response::builder()
                        .status(json.status_code())
                        .body(full(json.to_json().to_string()))
                        .unwrap()
                })
                .unwrap_or_else(|err_resp| err_resp),
            _ => Response::builder().status(StatusCode::NOT_FOUND).body(full("Not found")).unwrap(),
        };
        response
            .headers_mut()
            .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));
        Ok(response)
    }

    fn handle_get_bip21(
        &self,
        amount: Option<Amount>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        let v1_config = self.config.v1().map_err(|e| {
            Error::Implementation(ImplementationError::from(e.into_boxed_dyn_error()))
        })?;
        let address = self.wallet.get_new_address().map_err(|e| {
            Error::Implementation(ImplementationError::from(e.into_boxed_dyn_error()))
        })?;
        let uri_string = if let Some(amount) = amount {
            format!(
                "{}?amount={}&pj={}",
                address.to_qr_uri(),
                amount.to_btc(),
                v1_config.pj_endpoint
            )
        } else {
            format!("{}?pj={}", address.to_qr_uri(), v1_config.pj_endpoint)
        };
        let uri = Uri::try_from(uri_string.clone()).map_err(|_| {
            Error::Implementation(ImplementationError::from(
                anyhow!("Could not parse payjoin URI string.").into_boxed_dyn_error(),
            ))
        })?;
        let _ = uri.assume_checked(); // we just got it from bitcoind above

        Ok(Response::new(full(uri_string)))
    }

    async fn handle_payjoin_post(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        let (parts, body) = req.into_parts();
        let headers = Headers(&parts.headers);
        let query_string = parts.uri.query().unwrap_or("");
        let body = body
            .collect()
            .await
            .map_err(|e| Error::Implementation(ImplementationError::new(e)))?
            .to_bytes();
        let proposal = UncheckedOriginalPayload::from_request(&body, query_string, headers)?;

        let payjoin_proposal = self.process_v1_proposal(proposal)?;
        let psbt = payjoin_proposal.psbt();
        let body = psbt.to_string();
        println!(
            "Responded with Payjoin proposal {}",
            psbt.clone().extract_tx_unchecked_fee_rate().compute_txid()
        );
        Ok(Response::new(full(body)))
    }

    fn process_v1_proposal(
        &self,
        proposal: UncheckedOriginalPayload,
    ) -> Result<PayjoinProposal, Error> {
        let wallet = self.wallet();

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            wallet
                .can_broadcast(tx)
                .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
        })?;
        tracing::trace!("check1");

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(&mut |input| {
            wallet.is_mine(input).map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
        })?;
        tracing::trace!("check2");

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal.check_no_inputs_seen_before(&mut |input| {
            Ok(self.db.insert_input_seen_before(*input)?)
        })?;
        tracing::trace!("check3");

        let payjoin = payjoin.identify_receiver_outputs(&mut |output_script| {
            wallet
                .is_mine(output_script)
                .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
        })?;

        let payjoin = payjoin
            .substitute_receiver_script(
                &self
                    .wallet
                    .get_new_address()
                    .map_err(|e| {
                        Error::Implementation(ImplementationError::from(e.into_boxed_dyn_error()))
                    })?
                    .script_pubkey(),
            )
            .map_err(|e| Error::Implementation(ImplementationError::new(e)))?
            .commit_outputs();

        let wants_fee_range = try_contributing_inputs(payjoin.clone(), &self.wallet)
            .map_err(Error::Implementation)?;
        let provisional_payjoin =
            wants_fee_range.apply_fee_range(None, self.config.max_fee_rate)?;

        let payjoin_proposal = provisional_payjoin.finalize_proposal(|psbt| {
            self.wallet
                .process_psbt(psbt)
                .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
        })?;
        Ok(payjoin_proposal)
    }
}

fn try_contributing_inputs(
    payjoin: payjoin::receive::v1::WantsInputs,
    wallet: &BitcoindWallet,
) -> Result<payjoin::receive::v1::WantsFeeRange, ImplementationError> {
    let candidate_inputs =
        wallet.list_unspent().map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))?;

    let selected_input =
        payjoin.try_preserving_privacy(candidate_inputs).map_err(ImplementationError::new)?;

    Ok(payjoin
        .contribute_inputs(vec![selected_input])
        .map_err(ImplementationError::new)?
        .commit_inputs())
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}
