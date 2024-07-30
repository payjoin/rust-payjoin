use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::Amount;
use payjoin::receive::v2::ActiveSession;
use payjoin::send::RequestContext;
use payjoin::{bitcoin, Error, Uri};
use tokio::signal;
use tokio::sync::watch;

use super::config::AppConfig;
use super::App as AppTrait;
use crate::app::http_agent;
use crate::db::Database;

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    db: Arc<Database>,
    interrupt: watch::Receiver<()>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: AppConfig) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let app = Self { config, db, interrupt: interrupt_rx };
        app.bitcoind()?
            .get_blockchain_info()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
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
                    self.config.bitcoind_rpcpassword.clone(),
                ),
            ),
        }
        .with_context(|| "Failed to connect to bitcoind")
    }

    async fn send_payjoin(&self, bip21: &str, fee_rate: &f32) -> Result<()> {
        use payjoin::UriExt;
        let uri =
            Uri::try_from(bip21).map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;
        let uri = uri.assume_checked();
        let uri = uri.check_pj_supported().map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let url = uri.extras.endpoint();
        // match bip21 to send_session public_key
        let req_ctx = match self.db.get_send_session(url)? {
            Some(send_session) => send_session,
            None => {
                let mut req_ctx = self.create_pj_request(&uri, fee_rate)?;
                self.db.insert_send_session(&mut req_ctx, url)?;
                req_ctx
            }
        };
        self.spawn_payjoin_sender(req_ctx).await
    }

    async fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        use payjoin::receive::v2::SessionInitializer;

        let address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let mut initializer = SessionInitializer::new(
            address,
            self.config.pj_directory.clone(),
            ohttp_keys.clone(),
            self.config.ohttp_relay.clone(),
            None,
        );
        let (req, ctx) =
            initializer.extract_req().map_err(|e| anyhow!("Failed to extract request {}", e))?;
        println!("Starting new Payjoin session with {}", self.config.pj_directory);
        let http = http_agent()?;
        let ohttp_response = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        let session = initializer
            .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), ctx)
            .map_err(|e| anyhow!("Enrollment failed {}", e))?;
        self.db.insert_recv_session(session.clone())?;
        self.spawn_payjoin_receiver(session, Some(amount)).await
    }
}

impl App {
    async fn spawn_payjoin_sender(&self, mut req_ctx: RequestContext) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.long_poll_post(&mut req_ctx) => {
                self.process_pj_response(res?)?;
                self.db.clear_send_session(req_ctx.endpoint())?;
            }
            _ = interrupt.changed() => {
                println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
            }
        }
        Ok(())
    }

    async fn spawn_payjoin_receiver(
        &self,
        mut session: ActiveSession,
        amount: Option<Amount>,
    ) -> Result<()> {
        println!("Receive session established");
        let mut pj_uri_builder = session.pj_uri_builder();
        if let Some(amount) = amount {
            pj_uri_builder = pj_uri_builder.amount(amount);
        }
        let pj_uri = pj_uri_builder.build();

        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);

        let mut interrupt = self.interrupt.clone();
        let res = tokio::select! {
            res = self.long_poll_fallback(&mut session) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Ok(());
            }
        }?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&res.extract_tx_to_schedule_broadcast()));
        let mut payjoin_proposal = self
            .process_v2_proposal(res)
            .map_err(|e| anyhow!("Failed to process proposal {}", e))?;
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req()
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        println!("Got a request from the sender. Responding with a Payjoin proposal.");
        let http = http_agent()?;
        let res = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        payjoin_proposal
            .process_res(res.bytes().await?.to_vec(), ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = payjoin_proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().clone().compute_txid()
        );
        self.db.clear_recv_session()?;
        Ok(())
    }

    pub async fn resume_payjoins(&self) -> Result<()> {
        let recv_sessions = self.db.get_recv_sessions()?;
        let send_sessions = self.db.get_send_sessions()?;

        if recv_sessions.is_empty() && send_sessions.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        for session in recv_sessions {
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move {
                self_clone.spawn_payjoin_receiver(session, None).await
            }));
        }

        for session in send_sessions {
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move { self_clone.spawn_payjoin_sender(session).await }));
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = async {
                for task in tasks {
                    let _ = task.await;
                }
            } => {
                println!("All resumed sessions completed.");
            }
            _ = interrupt.changed() => {
                println!("Resumed sessions were interrupted.");
            }
        }
        Ok(())
    }

    async fn long_poll_post(&self, req_ctx: &mut payjoin::send::RequestContext) -> Result<Psbt> {
        loop {
            let (req, ctx) = req_ctx.extract_v2(self.config.ohttp_relay.clone())?;
            println!("Polling send request...");
            let http = http_agent()?;
            let response = http
                .post(req.url)
                .header("Content-Type", req.content_type)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            println!("Sent fallback transaction");
            match ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => {
                    println!("No response yet.");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: &mut payjoin::receive::v2::ActiveSession,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) = session.extract_req()?;
            println!("Polling receive request...");
            let http = http_agent()?;
            let ohttp_response = http
                .post(req.url)
                .header("Content-Type", req.content_type)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            let proposal = session
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context)
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
        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network = bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into()))?.chain;
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
            self.db.insert_input_seen_before(*input).map_err(|e| Error::Server(e.into()))
        })?;
        log::trace!("check4");

        let provisional_payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        let provisional_payjoin = provisional_payjoin.try_substitute_receiver_outputs(None)?;

        let provisional_payjoin = try_contributing_inputs(provisional_payjoin, &bitcoind)
            .map_err(|e| Error::Server(e.into()))?;

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(&psbt.to_string(), None, None, Some(false))
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);
        Ok(payjoin_proposal)
    }
}

fn try_contributing_inputs(
    payjoin: payjoin::receive::v2::WantsInputs,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<payjoin::receive::v2::ProvisionalProposal> {
    use bitcoin::OutPoint;

    let available_inputs = bitcoind
        .list_unspent(None, None, None, None, None)
        .context("Failed to list unspent from bitcoind")?;
    let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
        .iter()
        .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
        .collect();

    let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
        .context("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.")?;
    log::debug!("selected utxo: {:#?}", selected_utxo);

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = bitcoin::TxOut {
        value: selected_utxo.amount,
        script_pubkey: selected_utxo.script_pub_key.clone(),
    };
    Ok(payjoin.contribute_witness_input(txo_to_contribute, selected_outpoint))
}

async fn unwrap_ohttp_keys_or_else_fetch(config: &AppConfig) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let ohttp_relay = config.ohttp_relay.clone();
        let payjoin_directory = config.pj_directory.clone();
        #[cfg(feature = "danger-local-https")]
        let cert_der = crate::app::read_local_cert()?;
        Ok(payjoin::io::fetch_ohttp_keys(
            ohttp_relay,
            payjoin_directory,
            #[cfg(feature = "danger-local-https")]
            cert_der,
        )
        .await?)
    }
}

async fn handle_interrupt(tx: watch::Sender<()>) {
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("Error setting up Ctrl-C handler: {}", e);
    }
    let _ = tx.send(());
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}
