use std::fs::OpenOptions;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::Amount;
use payjoin::{base64, bitcoin, Error, PjUriBuilder};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::spawn_blocking;

use super::config::AppConfig;
use super::{App as AppTrait, SeenInputs};
use crate::app::http_agent;

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    receive_store: Arc<AsyncMutex<ReceiveStore>>,
    send_store: Arc<AsyncMutex<SendStore>>,
    seen_inputs: Arc<Mutex<SeenInputs>>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: AppConfig) -> Result<Self> {
        let seen_inputs = Arc::new(Mutex::new(SeenInputs::new()?));
        let receive_store = Arc::new(AsyncMutex::new(ReceiveStore::new()?));
        let send_store = Arc::new(AsyncMutex::new(SendStore::new()?));
        let app = Self { config, receive_store, send_store, seen_inputs };
        Ok(app)
    }

    fn bitcoind(&self) -> Result<bitcoincore_rpc::Client> {
        match &self.config.bitcoind_cookie {
            Some(cookie) => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::CookieFile(cookie.into()),
            ),
            None => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::UserPass(
                    self.config.bitcoind_rpcuser.clone(),
                    self.config.bitcoind_rpcpass.clone(),
                ),
            ),
        }
        .with_context(|| "Failed to connect to bitcoind")
    }

    async fn send_payjoin(&self, bip21: &str, fee_rate: &f32, is_retry: bool) -> Result<()> {
        let mut session = self.send_store.lock().await;
        let req_ctx = if is_retry {
            log::debug!("Resuming session");
            // Get a reference to RequestContext
            session.req_ctx.as_mut().expect("RequestContext is missing")
        } else {
            let req_ctx = self.create_pj_request(bip21, fee_rate)?;
            session.write(req_ctx)?;
            log::debug!("Writing req_ctx");
            session.req_ctx.as_mut().expect("RequestContext is missing")
        };
        log::debug!("Awaiting response");
        let res = self.long_poll_post(req_ctx).await?;
        self.process_pj_response(res)?;
        session.clear()?;
        Ok(())
    }

    async fn receive_payjoin(self, amount_arg: &str, is_retry: bool) -> Result<()> {
        use payjoin::receive::v2::Enroller;

        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let mut enrolled = if !is_retry {
            let mut enroller = Enroller::from_directory_config(
                self.config.pj_endpoint.clone(),
                ohttp_keys.clone(),
                self.config.ohttp_relay.clone(),
            );
            let (req, ctx) =
                enroller.extract_req().map_err(|e| anyhow!("Failed to extract request {}", e))?;
            log::debug!("Enrolling receiver");
            let http = http_agent()?;
            let ohttp_response = spawn_blocking(move || {
                http.post(req.url.as_ref())
                    .set("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                    .send_bytes(&req.body)
                    .map_err(map_ureq_err)
            })
            .await??;

            let enrolled = enroller
                .process_res(ohttp_response.into_reader(), ctx)
                .map_err(|_| anyhow!("Enrollment failed"))?;
            self.receive_store.lock().await.write(enrolled.clone())?;
            enrolled
        } else {
            let session = self.receive_store.lock().await;
            log::debug!("Resuming session");
            session.session.clone().ok_or(anyhow!("No session found"))?
        };

        log::debug!("Enrolled receiver");
        let pj_uri_string =
            self.construct_payjoin_uri(amount_arg, &enrolled.fallback_target(), ohttp_keys)?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        log::debug!("Awaiting proposal");
        let res = self.long_poll_fallback(&mut enrolled).await?;
        log::debug!("Received request");
        let mut payjoin_proposal = self
            .process_v2_proposal(res)
            .map_err(|e| anyhow!("Failed to process proposal {}", e))?;
        log::debug!("Posting payjoin back");
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req()
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let http = http_agent()?;
        let res = http
            .post(req.url.as_str())
            .set("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
            .send_bytes(&req.body)
            .map_err(map_ureq_err)?;
        let mut buf = Vec::new();
        let _ = res.into_reader().read_to_end(&mut buf)?;
        let res = payjoin_proposal
            .deserialize_res(buf, ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        log::debug!("Received response {:?}", res);
        self.receive_store.lock().await.clear()?;
        Ok(())
    }
}

impl App {
    fn construct_payjoin_uri(
        &self,
        amount_arg: &str,
        fallback_target: &str,
        ohttp_keys: payjoin::OhttpKeys,
    ) -> Result<String> {
        let pj_receiver_address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_part = payjoin::Url::parse(fallback_target)
            .map_err(|e| anyhow!("Failed to parse pj_endpoint: {}", e))?;

        let pj_uri = PjUriBuilder::new(pj_receiver_address, pj_part, Some(ohttp_keys))
            .amount(amount)
            .build();

        Ok(pj_uri.to_string())
    }

    async fn long_poll_post(&self, req_ctx: &mut payjoin::send::RequestContext) -> Result<Psbt> {
        loop {
            let (req, ctx) = req_ctx.extract_v2(self.config.ohttp_relay.clone())?;
            println!("Sending fallback request to {}", &req.url);
            let http = http_agent()?;
            let response = spawn_blocking(move || {
                http.post(req.url.as_ref())
                    .set("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                    .send_bytes(&req.body)
                    .map_err(map_ureq_err)
            })
            .await??;

            println!("Sent fallback transaction");
            match ctx.process_response(&mut response.into_reader()) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => std::thread::sleep(std::time::Duration::from_secs(5)),
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        enrolled: &mut payjoin::receive::v2::Enrolled,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) =
                enrolled.extract_req().map_err(|_| anyhow!("Failed to extract request"))?;
            log::debug!("GET fallback_psbt");
            let http = http_agent()?;
            let ohttp_response = spawn_blocking(move || {
                http.post(req.url.as_str())
                    .set("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                    .send_bytes(&req.body)
                    .map_err(map_ureq_err)
            })
            .await??;

            let proposal = enrolled
                .process_res(ohttp_response.into_reader(), context)
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            match proposal {
                Some(proposal) => break Ok(proposal),
                None => std::thread::sleep(std::time::Duration::from_secs(5)),
            }
        }
    }

    fn process_v2_proposal(
        &self,
        proposal: payjoin::receive::v2::UncheckedProposal,
    ) -> Result<payjoin::receive::v2::PayjoinProposal, Error> {
        use crate::app::try_contributing_inputs;

        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            let mempool_results =
                bitcoind.test_mempool_accept(&[raw_tx]).map_err(|e| Error::Server(e.into()))?;
            match mempool_results.first() {
                Some(result) => Ok(result.allowed),
                None => Err(Error::Server(
                    anyhow!("No mempool results returned on broadcast check").into(),
                )),
            }
        })?;
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            if let Ok(address) = bitcoin::Address::from_script(input, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;
        log::trace!("check2");
        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts()?;
        log::trace!("check3");

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal.check_no_inputs_seen_before(|input| {
            Ok(!self.insert_input_seen_before(*input).map_err(|e| Error::Server(e.into()))?)
        })?;
        log::trace!("check4");

        let mut provisional_payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        if !self.config.sub_only {
            // Select receiver payjoin inputs.
            _ = try_contributing_inputs(&mut provisional_payjoin.inner, &bitcoind)
                .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));
        }

        if !provisional_payjoin.is_output_substitution_disabled() {
            // Substitute the receiver output address.
            let receiver_substitute_address = bitcoind
                .get_new_address(None, None)
                .map_err(|e| Error::Server(e.into()))?
                .assume_checked();
            provisional_payjoin.substitute_output_address(receiver_substitute_address);
        }

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, Some(false))
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);
        Ok(payjoin_proposal)
    }

    fn insert_input_seen_before(&self, input: bitcoin::OutPoint) -> Result<bool> {
        self.seen_inputs.lock().expect("mutex lock failed").insert(input)
    }
}

async fn unwrap_ohttp_keys_or_else_fetch(config: &AppConfig) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.ohttp_keys.clone() {
        Ok(keys)
    } else {
        let ohttp_relay = config.ohttp_relay.clone();
        let payjoin_directory = config.pj_endpoint.clone();
        #[cfg(feature = "danger-local-https")]
        let cert_der = rcgen::generate_simple_self_signed(vec![
            "0.0.0.0".to_string(),
            "localhost".to_string(),
        ])?
        .serialize_der()?;
        #[cfg(not(feature = "danger-local-https"))]
        return Ok(payjoin_defaults::fetch_ohttp_keys(ohttp_relay, payjoin_directory).await?);
        #[cfg(feature = "danger-local-https")]
        Ok(payjoin_defaults::fetch_ohttp_keys(ohttp_relay, payjoin_directory, cert_der).await?)
    }
}

fn map_ureq_err(e: ureq::Error) -> anyhow::Error {
    let e_string = e.to_string();
    match e.into_response() {
        Some(res) => anyhow!(
            "HTTP request failed: {} {}",
            res.status(),
            res.into_string().unwrap_or_default()
        ),
        None => anyhow!("No HTTP response: {}", e_string),
    }
}

struct SendStore {
    req_ctx: Option<payjoin::send::RequestContext>,
    file: std::fs::File,
}

impl SendStore {
    fn new() -> Result<Self> {
        let mut file =
            OpenOptions::new().write(true).read(true).create(true).open("send_store.json")?;
        let session = match serde_json::from_reader(&mut file) {
            Ok(session) => Some(session),
            Err(e) => {
                log::debug!("error reading send session store: {}", e);
                None
            }
        };

        Ok(Self { req_ctx: session, file })
    }

    fn write(
        &mut self,
        session: payjoin::send::RequestContext,
    ) -> Result<&mut payjoin::send::RequestContext> {
        use std::io::Write;

        let session = self.req_ctx.insert(session);
        let serialized = serde_json::to_string(session)?;
        self.file.write_all(serialized.as_bytes())?;
        Ok(session)
    }

    fn clear(&mut self) -> Result<()> {
        let file = OpenOptions::new().write(true).open("send_store.json")?;
        file.set_len(0)?;
        Ok(())
    }
}

struct ReceiveStore {
    session: Option<payjoin::receive::v2::Enrolled>,
    file: std::fs::File,
}

impl ReceiveStore {
    fn new() -> Result<Self> {
        let mut file =
            OpenOptions::new().write(true).read(true).create(true).open("receive_store.json")?;
        let session = match serde_json::from_reader(&mut file) {
            Ok(session) => Some(session),
            Err(e) => {
                log::debug!("error reading receive session store: {}", e);
                None
            }
        };

        Ok(Self { session, file })
    }

    fn write(
        &mut self,
        session: payjoin::receive::v2::Enrolled,
    ) -> Result<&mut payjoin::receive::v2::Enrolled> {
        use std::io::Write;

        let session = self.session.insert(session);
        let serialized = serde_json::to_string(session)?;
        self.file.write_all(serialized.as_bytes())?;
        Ok(session)
    }

    fn clear(&mut self) -> Result<()> {
        let file = OpenOptions::new().write(true).open("receive_store.json")?;
        file.set_len(0)?;
        Ok(())
    }
}
