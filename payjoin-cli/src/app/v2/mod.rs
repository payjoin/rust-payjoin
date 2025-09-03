use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::OptionalTransitionOutcome;
use payjoin::receive::v2::{
    process_err_res, replay_event_log as replay_receiver_event_log, Initialized, MaybeInputsOwned,
    MaybeInputsSeen, OutputsUnknown, PayjoinProposal, ProvisionalProposal, ReceiveSession,
    Receiver, ReceiverBuilder, SessionHistory, UncheckedOriginalPayload, WantsFeeRange,
    WantsInputs, WantsOutputs,
};
use payjoin::send::v2::{
    replay_event_log as replay_sender_event_log, SendSession, Sender, SenderBuilder, V2GetContext,
    WithReplyKey,
};
use payjoin::{ImplementationError, PjParam, Uri};
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
use crate::app::v2::ohttp::{unwrap_ohttp_keys_or_else_fetch, RelayManager};
use crate::app::{handle_interrupt, http_agent};
use crate::db::v2::{ReceiverPersister, SenderPersister};
use crate::db::Database;

mod ohttp;

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
    relay_manager: Arc<Mutex<RelayManager>>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    async fn new(config: Config) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx, relay_manager };
        app.wallet()
            .network()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn wallet(&self) -> BitcoindWallet { self.wallet.clone() }

    #[allow(clippy::incompatible_msrv)]
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        use payjoin::UriExt;
        let uri = Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?
            .assume_checked()
            .check_pj_supported()
            .map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let address = uri.address;
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;
        match uri.extras.pj_param() {
            #[cfg(feature = "v1")]
            PjParam::V1(pj_param) => {
                use std::str::FromStr;

                let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                let (req, ctx) = payjoin::send::v1::SenderBuilder::from_parts(
                    psbt,
                    pj_param,
                    &address,
                    Some(amount),
                )
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
                let fallback_tx = payjoin::bitcoin::Psbt::from_str(&body)
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
            PjParam::V2(pj_param) => {
                let receiver_pubkey = pj_param.receiver_pubkey();
                let session_id = self.db.get_send_session_id_with_receiver_pk(receiver_pubkey)?;
                let sender_state = match session_id {
                    Some(session_id) => {
                        let sender_persister =
                            SenderPersister::from_id(self.db.clone(), session_id)?;
                        let (send_session, _) = replay_sender_event_log(&sender_persister)?;
                        Some((send_session, sender_persister))
                    }
                    None => None,
                };

                let (sender_state, persister) = match sender_state {
                    Some((sender_state, persister)) => (sender_state, persister),
                    None => {
                        let persister =
                            SenderPersister::new(self.db.clone(), receiver_pubkey.clone())?;
                        let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                        let sender =
                            SenderBuilder::from_parts(psbt, pj_param, &address, Some(amount))
                                .build_recommended(fee_rate)?
                                .save(&persister)?;

                        (SendSession::WithReplyKey(sender), persister)
                    }
                };
                let mut interrupt = self.interrupt.clone();
                tokio::select! {
                    _ = self.process_sender_session(sender_state, &persister) => return Ok(()),
                    _ = interrupt.changed() => {
                        println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
                        return Err(anyhow!("Interrupted"))
                    }
                }
            }
            _ => unimplemented!("Unrecognized payjoin version"),
        }
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let address = self.wallet().get_new_address()?;
        let ohttp_keys =
            unwrap_ohttp_keys_or_else_fetch(&self.config, None, self.relay_manager.clone())
                .await?
                .ohttp_keys;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let session =
            ReceiverBuilder::new(address, self.config.v2()?.pj_directory.clone(), ohttp_keys)?
                .with_amount(amount)
                .with_max_fee_rate(self.config.max_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN))
                .build()
                .save(&persister)?;

        println!("Receive session established");
        let pj_uri = session.pj_uri();
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);

        self.process_receiver_session(ReceiveSession::Initialized(session.clone()), &persister)
            .await?;
        Ok(())
    }

    #[allow(clippy::incompatible_msrv)]
    async fn resume_payjoins(&self) -> Result<()> {
        let recv_session_ids = self.db.get_recv_session_ids()?;
        let send_session_ids = self.db.get_send_session_ids()?;

        if recv_session_ids.is_empty() && send_session_ids.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        for session_id in recv_session_ids {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id)?;
            let receiver_state = replay_receiver_event_log(&recv_persister)
                .map_err(|e| anyhow!("Failed to replay receiver event log: {:?}", e))?
                .0;
            tasks.push(tokio::spawn(async move {
                self_clone.process_receiver_session(receiver_state, &recv_persister).await
            }));
        }

        for session_id in send_session_ids {
            let sender_persiter = SenderPersister::from_id(self.db.clone(), session_id)?;
            let sender_state = replay_sender_event_log(&sender_persiter)
                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))?
                .0;
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move {
                self_clone.process_sender_session(sender_state, &sender_persiter).await
            }));
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
}

impl App {
    async fn process_sender_session(
        &self,
        session: SendSession,
        persister: &SenderPersister,
    ) -> Result<()> {
        match session {
            SendSession::WithReplyKey(context) =>
                self.post_original_proposal(context, persister).await?,
            SendSession::V2GetContext(context) =>
                self.get_proposed_payjoin_psbt(context, persister).await?,
            SendSession::ProposalReceived(proposal) => {
                self.process_pj_response(proposal)?;
                return Ok(());
            }
            _ => return Err(anyhow!("Unexpected sender state")),
        }
        Ok(())
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        persister: &SenderPersister,
    ) -> Result<()> {
        let (req, ctx) = sender.create_v2_post_request(
            self.unwrap_relay_or_else_fetch(Some(sender.endpoint().clone())).await?,
        )?;
        let response = self.post_request(req).await?;
        println!("Posted original proposal...");
        let sender = sender.process_response(&response.bytes().await?, ctx).save(persister)?;
        self.get_proposed_payjoin_psbt(sender, persister).await
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<V2GetContext>,
        persister: &SenderPersister,
    ) -> Result<()> {
        let mut session = sender.clone();
        // Long poll until we get a response
        loop {
            let (req, ctx) = session.create_poll_request(
                self.unwrap_relay_or_else_fetch(Some(session.endpoint().clone())).await?,
            )?;
            let response = self.post_request(req).await?;
            let res = session.process_response(&response.bytes().await?, ctx).save(persister);
            match res {
                Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                    println!("Proposal received. Processing...");
                    self.process_pj_response(psbt)?;
                    return Ok(());
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    println!("No response yet.");
                    session = current_state;
                    continue;
                }
                Err(re) => {
                    println!("{re}");
                    tracing::debug!("{re:?}");
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
    ) -> Result<Receiver<UncheckedOriginalPayload>> {
        let ohttp_relay = self
            .unwrap_relay_or_else_fetch(Some(session.pj_uri().extras.endpoint().clone()))
            .await?;

        let mut session = session;
        loop {
            let (req, context) = session.create_poll_request(&ohttp_relay)?;
            println!("Polling receive request...");
            let ohttp_response = self.post_request(req).await?;
            let state_transition = session
                .process_response(ohttp_response.bytes().await?.to_vec().as_slice(), context)
                .save(persister);
            match state_transition {
                Ok(OptionalTransitionOutcome::Progress(next_state)) => {
                    println!("Got a request from the sender. Responding with a Payjoin proposal.");
                    return Ok(next_state);
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    session = current_state;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn process_receiver_session(
        &self,
        session: ReceiveSession,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let res = {
            match session {
                ReceiveSession::Initialized(proposal) =>
                    self.read_from_directory(proposal, persister).await,
                ReceiveSession::UncheckedOriginalPayload(proposal) =>
                    self.check_proposal(proposal, persister).await,
                ReceiveSession::MaybeInputsOwned(proposal) =>
                    self.check_inputs_not_owned(proposal, persister).await,
                ReceiveSession::MaybeInputsSeen(proposal) =>
                    self.check_no_inputs_seen_before(proposal, persister).await,
                ReceiveSession::OutputsUnknown(proposal) =>
                    self.identify_receiver_outputs(proposal, persister).await,
                ReceiveSession::WantsOutputs(proposal) =>
                    self.commit_outputs(proposal, persister).await,
                ReceiveSession::WantsInputs(proposal) =>
                    self.contribute_inputs(proposal, persister).await,
                ReceiveSession::WantsFeeRange(proposal) =>
                    self.apply_fee_range(proposal, persister).await,
                ReceiveSession::ProvisionalProposal(proposal) =>
                    self.finalize_proposal(proposal, persister).await,
                ReceiveSession::PayjoinProposal(proposal) =>
                    self.send_payjoin_proposal(proposal, persister).await,
                ReceiveSession::Uninitialized =>
                    return Err(anyhow!("Uninitialized receiver session")),
                ReceiveSession::TerminalFailure =>
                    return Err(anyhow!("Terminal receiver session")),
            }
        };

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                let (_, session_history) = replay_receiver_event_log(persister)?;
                let pj_uri = match session_history.pj_uri() {
                    Some(uri) => Some(uri.extras.endpoint().clone()),
                    None => None,
                };
                let ohttp_relay = self.unwrap_relay_or_else_fetch(pj_uri).await?;
                self.handle_recoverable_error(&ohttp_relay, &session_history).await?;

                Err(e)
            }
        }
    }

    #[allow(clippy::incompatible_msrv)]
    async fn read_from_directory(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(session, persister) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;
        self.check_proposal(receiver, persister).await
    }

    async fn check_proposal(
        &self,
        proposal: Receiver<UncheckedOriginalPayload>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_broadcast_suitability(None, |tx| {
                wallet
                    .can_broadcast(tx)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&proposal.extract_tx_to_schedule_broadcast()));
        self.check_inputs_not_owned(proposal, persister).await
    }

    async fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_inputs_not_owned(&mut |input| {
                wallet
                    .is_mine(input)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.check_no_inputs_seen_before(proposal, persister).await
    }

    async fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal
            .check_no_inputs_seen_before(&mut |input| {
                Ok(self.db.insert_input_seen_before(*input)?)
            })
            .save(persister)?;
        self.identify_receiver_outputs(proposal, persister).await
    }

    async fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .identify_receiver_outputs(&mut |output_script| {
                wallet
                    .is_mine(output_script)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.commit_outputs(proposal, persister).await
    }

    async fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal.commit_outputs().save(persister)?;
        self.contribute_inputs(proposal, persister).await
    }

    async fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let candidate_inputs = wallet.list_unspent()?;

        let selected_input = proposal.try_preserving_privacy(candidate_inputs)?;
        let proposal =
            proposal.contribute_inputs(vec![selected_input])?.commit_inputs().save(persister)?;
        self.apply_fee_range(proposal, persister).await
    }

    async fn apply_fee_range(
        &self,
        proposal: Receiver<WantsFeeRange>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let proposal = proposal.apply_fee_range(None, self.config.max_fee_rate).save(persister)?;
        self.finalize_proposal(proposal, persister).await
    }

    async fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .finalize_proposal(|psbt| {
                wallet
                    .process_psbt(psbt)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.send_payjoin_proposal(proposal, persister).await
    }

    async fn send_payjoin_proposal(
        &self,
        mut proposal: Receiver<PayjoinProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let (req, ohttp_ctx) = proposal
            .create_post_request(&self.unwrap_relay_or_else_fetch(None).await?)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let res = self.post_request(req).await?;
        let payjoin_psbt = proposal.psbt().clone();
        proposal.process_response(&res.bytes().await?, ohttp_ctx).save(persister)?;
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().compute_txid()
        );
        Ok(())
    }

    async fn unwrap_relay_or_else_fetch(
        &self,
        directory: Option<payjoin::Url>,
    ) -> Result<payjoin::Url> {
        let selected_relay =
            self.relay_manager.lock().expect("Lock should not be poisoned").get_selected_relay();
        let ohttp_relay = match selected_relay {
            Some(relay) => relay,
            None =>
                unwrap_ohttp_keys_or_else_fetch(&self.config, directory, self.relay_manager.clone())
                    .await?
                    .relay_url,
        };
        Ok(ohttp_relay)
    }

    /// Handle request error by sending an error response over the directory
    async fn handle_recoverable_error(
        &self,
        ohttp_relay: &payjoin::Url,
        session_history: &SessionHistory,
    ) -> Result<()> {
        let e = match session_history.terminal_error() {
            Some((_, Some(e))) => e,
            _ => return Ok(()),
        };
        let (err_req, err_ctx) = session_history
            .extract_err_req(ohttp_relay)?
            .expect("If JsonReply is Some, then err_req and err_ctx should be Some");
        let to_return = anyhow!("Replied with error: {}", e.to_json().to_string());

        let err_response = match self.post_request(err_req).await {
            Ok(response) => response,
            Err(e) => return Err(anyhow!("Failed to post error request: {}", e)),
        };

        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(anyhow!("Failed to get error response bytes: {}", e)),
        };

        if let Err(e) = process_err_res(&err_bytes, err_ctx) {
            return Err(anyhow!("Failed to process error response: {}", e));
        }

        Err(to_return)
    }

    async fn post_request(&self, req: payjoin::Request) -> Result<reqwest::Response> {
        let http = http_agent(&self.config)?;
        http.post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)
    }
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}
