use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::receive::v2::{
    replay_event_log as replay_receiver_event_log, HasReplyableError, Initialized,
    MaybeInputsOwned, MaybeInputsSeen, Monitor, OutputsUnknown, PayjoinProposal,
    ProvisionalProposal, ReceiveSession, Receiver, ReceiverBuilder,
    SessionOutcome as ReceiverSessionOutcome, UncheckedOriginalPayload, WantsFeeRange, WantsInputs,
    WantsOutputs,
};
use payjoin::send::v2::{
    replay_event_log as replay_sender_event_log, PollingForProposal, SendSession, Sender,
    SenderBuilder, SessionOutcome as SenderSessionOutcome, WithReplyKey,
};
use payjoin::{ImplementationError, PjParam, Uri};
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
use crate::app::handle_interrupt;
#[cfg(feature = "v1")]
use crate::app::http_agent;
use crate::app::v2::ohttp::{
    classify_reqwest_error, http_client_builder, unwrap_ohttp_keys_or_else_fetch,
    RelayAttemptError, RelaySession,
};
use crate::db::v2::{ReceiverPersister, SenderPersister, SessionId};
use crate::db::Database;

pub(crate) mod asmap;
mod ohttp;
pub(crate) mod relay_selection;

const W_ID: usize = 12;
const W_ROLE: usize = 25;
const W_DONE: usize = 15;
const W_STATUS: usize = 15;

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
}

trait StatusText {
    fn status_text(&self) -> &'static str;
}

impl StatusText for SendSession {
    fn status_text(&self) -> &'static str {
        match self {
            SendSession::WithReplyKey(_) | SendSession::PollingForProposal(_) =>
                "Waiting for proposal",
            SendSession::Closed(session_outcome) => match session_outcome {
                SenderSessionOutcome::Failure => "Session failure",
                SenderSessionOutcome::Success(_) => "Session success",
                SenderSessionOutcome::Cancel => "Session cancelled",
            },
        }
    }
}

impl StatusText for ReceiveSession {
    fn status_text(&self) -> &'static str {
        match self {
            ReceiveSession::Initialized(_) => "Waiting for original proposal",
            ReceiveSession::UncheckedOriginalPayload(_)
            | ReceiveSession::MaybeInputsOwned(_)
            | ReceiveSession::MaybeInputsSeen(_)
            | ReceiveSession::OutputsUnknown(_)
            | ReceiveSession::WantsOutputs(_)
            | ReceiveSession::WantsInputs(_)
            | ReceiveSession::WantsFeeRange(_)
            | ReceiveSession::ProvisionalProposal(_) => "Processing original proposal",
            ReceiveSession::PayjoinProposal(_) => "Payjoin proposal sent",
            ReceiveSession::HasReplyableError(_) =>
                "Session failure, waiting to post error response",
            ReceiveSession::Monitor(_) => "Monitoring payjoin proposal",
            ReceiveSession::Closed(session_outcome) => match session_outcome {
                ReceiverSessionOutcome::Failure => "Session failure",
                ReceiverSessionOutcome::Success(_) => "Session success, Payjoin proposal was broadcasted",
                ReceiverSessionOutcome::Cancel => "Session cancelled",
                ReceiverSessionOutcome::FallbackBroadcasted => "Fallback broadcasted",
                ReceiverSessionOutcome::PayjoinProposalSent =>
                    "Payjoin proposal sent, skipping monitoring as the sender is spending non-SegWit inputs",
            },
        }
    }
}

fn print_header() {
    println!(
        "{:<W_ID$} {:<W_ROLE$} {:<W_DONE$} {:<W_STATUS$}",
        "Session ID", "Sender/Receiver", "Completed At", "Status"
    );
}

enum Role {
    Sender,
    Receiver,
}
impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Sender => "Sender",
            Role::Receiver => "Receiver",
        }
    }
}

struct SessionHistoryRow<Status> {
    session_id: SessionId,
    role: Role,
    status: Status,
    completed_at: Option<u64>,
    error_message: Option<String>,
}

impl<Status: StatusText> fmt::Display for SessionHistoryRow<Status> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<W_ID$} {:<W_ROLE$} {:<W_DONE$} {:<W_STATUS$}",
            self.session_id.to_string(),
            self.role.as_str(),
            match self.completed_at {
                None => "Not Completed".to_string(),
                Some(secs) => {
                    // TODO: human readable time
                    secs.to_string()
                }
            },
            self.error_message.as_deref().unwrap_or(self.status.status_text())
        )
    }
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

    #[allow(clippy::incompatible_msrv)]
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        use payjoin::UriExt;
        let uri = Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?
            .assume_checked()
            .check_pj_supported()
            .map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let pj_endpoint = uri.extras.endpoint();
        let address = uri.address;
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;
        match uri.extras.pj_param() {
            #[cfg(feature = "v1")]
            PjParam::V1(pj_param) => {
                let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                let fallback_tx = psbt.clone().extract_tx()?;
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
                println!("Sending Original PSBT to {}", req.url);
                let response = match http
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(body.clone())
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!("HTTP request failed: {e}");
                        println!("Payjoin failed. To broadcast the fallback transaction, run:");
                        println!(
                            "  bitcoin-cli -rpcwallet=<wallet> sendrawtransaction {:#}",
                            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
                        );
                        return Err(anyhow!("HTTP request failed: {e}"));
                    }
                };
                let psbt = match ctx.process_response(&response.bytes().await?) {
                    Ok(psbt) => psbt,
                    Err(e) => {
                        tracing::error!("Error processing response: {e:?}");
                        println!("Payjoin failed. To broadcast the fallback transaction, run:");
                        println!(
                            "  bitcoin-cli -rpcwallet=<wallet> sendrawtransaction {:#}",
                            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
                        );
                        return Err(anyhow!("Failed to process response {e}"));
                    }
                };

                self.process_pj_response(psbt)?;
                Ok(())
            }
            PjParam::V2(pj_param) => {
                relay_selection::ensure_trusted_sender_directory(self.config.v2()?, &pj_endpoint)?;
                let receiver_pubkey = pj_param.receiver_pubkey();
                let sender_state =
                    self.db.get_send_session_ids()?.into_iter().find_map(|session_id| {
                        let session_receiver_pubkey = self
                            .db
                            .get_send_session_receiver_pk(&session_id)
                            .expect("Receiver pubkey should exist if session id exists");
                        if session_receiver_pubkey == *receiver_pubkey {
                            let sender_persister =
                                SenderPersister::from_id(self.db.clone(), session_id);
                            let (send_session, _) = replay_sender_event_log(&sender_persister)
                                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))
                                .ok()?;

                            Some((send_session, sender_persister))
                        } else {
                            None
                        }
                    });

                let (sender_state, persister) = match sender_state {
                    Some((sender_state, persister)) => (sender_state, persister),
                    None => {
                        let persister =
                            SenderPersister::new(self.db.clone(), bip21, receiver_pubkey)?;
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
                    res = self.process_sender_session(sender_state, &persister) => {
                        match res {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                let id = persister.session_id();
                                println!("Session {id} failed. Run `payjoin-cli fallback {id}` to broadcast the original transaction.");
                                return Err(err);
                            }
                        }
                    },
                    _ = interrupt.changed() => {
                        let id = persister.session_id();
                        println!(
                            "Session {id} interrupted. Call `send` again to resume, `resume` to resume all sessions, or `payjoin-cli fallback {id}` to broadcast the original transaction."
                        );
                        return Err(anyhow!("Interrupted"))
                    }
                }
            }
            _ => unimplemented!("Unrecognized payjoin version"),
        }
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let address = self.wallet().get_new_address()?;
        let mut bootstrap_session =
            RelaySession::new(relay_selection::choose_receiver_bootstrap_plan(self.config.v2()?)?);
        let ohttp_keys =
            unwrap_ohttp_keys_or_else_fetch(&self.config, &mut bootstrap_session).await?.ohttp_keys;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let session =
            ReceiverBuilder::new(address, bootstrap_session.directory().url.as_str(), ohttp_keys)?
                .with_amount(amount)
                .with_max_fee_rate(self.config.max_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN))
                .build()
                .save(&persister)?;

        println!("Receive session established");
        let pj_uri = session.pj_uri();
        let receiver_endpoint = pj_uri.extras.endpoint();
        let mut relay_session = RelaySession::new(self.receiver_relay_plan(&receiver_endpoint)?);
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        self.process_receiver_session(
            ReceiveSession::Initialized(session.clone()),
            &persister,
            &mut relay_session,
        )
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

        // Process receiver sessions
        for session_id in recv_session_ids {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&recv_persister) {
                Ok((receiver_state, history)) => {
                    let receiver_endpoint = history.pj_uri().extras.endpoint();
                    let mut relay_session = match self_clone.receiver_relay_plan(&receiver_endpoint)
                    {
                        Ok(plan) => RelaySession::new(plan),
                        Err(error) => {
                            tracing::error!(
                                "Failed to derive relay plan for receiver session {}: {:?}",
                                session_id,
                                error
                            );
                            continue;
                        }
                    };
                    tasks.push(tokio::spawn(async move {
                        self_clone
                            .process_receiver_session(
                                receiver_state,
                                &recv_persister,
                                &mut relay_session,
                            )
                            .await
                    }));
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying receiver session", e);
                    Self::close_failed_session(&recv_persister, &session_id, "receiver");
                }
            }
        }

        // Process sender sessions
        for session_id in send_session_ids {
            let sender_persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&sender_persister) {
                Ok((sender_state, _)) => {
                    let self_clone = self.clone();
                    tasks.push(tokio::spawn(async move {
                        self_clone.process_sender_session(sender_state, &sender_persister).await
                    }));
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying Sender session", e);
                    Self::close_failed_session(&sender_persister, &session_id, "sender");
                }
            }
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

    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()> {
        print_header();
        let mut send_rows = vec![];
        let mut recv_rows = vec![];
        self.db.get_send_session_ids()?.into_iter().for_each(|session_id| {
            let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&persister) {
                Ok((sender_state, _)) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: sender_state.clone(),
                        completed_at: None,
                        error_message: None,
                    };
                    send_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: SendSession::Closed(SenderSessionOutcome::Failure),
                        completed_at: None,
                        error_message: Some(e.to_string()),
                    };
                    send_rows.push(row);
                }
            }
        });

        self.db.get_recv_session_ids()?.into_iter().for_each(|session_id| {
            let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&persister) {
                Ok((receiver_state, _)) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: receiver_state.clone(),
                        completed_at: None,
                        error_message: None,
                    };
                    recv_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: ReceiveSession::Closed(ReceiverSessionOutcome::Failure),
                        completed_at: None,
                        error_message: Some(e.to_string()),
                    };
                    recv_rows.push(row);
                }
            }
        });

        self.db.get_inactive_send_session_ids()?.into_iter().for_each(
            |(session_id, completed_at)| {
                let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
                match replay_sender_event_log(&persister) {
                    Ok((sender_state, _)) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Sender,
                            status: sender_state.clone(),
                            completed_at: Some(completed_at),
                            error_message: None,
                        };
                        send_rows.push(row);
                    }
                    Err(e) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Sender,
                            status: SendSession::Closed(SenderSessionOutcome::Failure),
                            completed_at: Some(completed_at),
                            error_message: Some(e.to_string()),
                        };
                        send_rows.push(row);
                    }
                }
            },
        );

        self.db.get_inactive_recv_session_ids()?.into_iter().for_each(
            |(session_id, completed_at)| {
                let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
                match replay_receiver_event_log(&persister) {
                    Ok((receiver_state, _)) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Receiver,
                            status: receiver_state.clone(),
                            completed_at: Some(completed_at),
                            error_message: None,
                        };
                        recv_rows.push(row);
                    }
                    Err(e) => {
                        let row = SessionHistoryRow {
                            session_id,
                            role: Role::Receiver,
                            status: ReceiveSession::Closed(ReceiverSessionOutcome::Failure),
                            completed_at: Some(completed_at),
                            error_message: Some(e.to_string()),
                        };
                        recv_rows.push(row);
                    }
                }
            },
        );

        // Print receiver and sender rows separately
        for row in send_rows {
            println!("{row}");
        }
        for row in recv_rows {
            println!("{row}");
        }

        Ok(())
    }

    async fn fallback_sender(&self, session_id: SessionId) -> Result<()> {
        let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
        let (session, history) = replay_sender_event_log(&persister)?;

        if let SendSession::Closed(SenderSessionOutcome::Success(proposal)) = session {
            let txid = proposal.clone().extract_tx_unchecked_fee_rate().compute_txid();
            println!(
                "Session {session_id} already produced payjoin transaction {txid}. \
                 Broadcasting the original now would double-spend against it. \
                 If the payjoin tx needs re-broadcast, run \
                 `bitcoin-cli gettransaction {txid}` to fetch the hex, then \
                 `bitcoin-cli sendrawtransaction <hex>`."
            );
            return Ok(());
        }

        let fallback_tx = history.fallback_tx();
        self.wallet().broadcast_tx(&fallback_tx)?;
        println!("Broadcasted fallback transaction txid: {}", fallback_tx.compute_txid());

        if let Err(e) = SessionPersister::close(&persister) {
            tracing::warn!("Failed to close session {session_id} after fallback: {e}");
        }
        Ok(())
    }
}

impl App {
    fn close_failed_session<P>(persister: &P, session_id: &SessionId, role: &str)
    where
        P: SessionPersister,
    {
        if let Err(close_err) = SessionPersister::close(persister) {
            tracing::error!("Failed to close {} session {}: {:?}", role, session_id, close_err);
        } else {
            tracing::error!("Closed failed {} session: {}", role, session_id);
        }
    }

    async fn process_sender_session(
        &self,
        session: SendSession,
        persister: &SenderPersister,
    ) -> Result<()> {
        match session {
            SendSession::WithReplyKey(context) => {
                let mut relay_session =
                    RelaySession::new(self.sender_relay_plan(&context.endpoint())?);
                self.post_original_proposal(context, persister, &mut relay_session).await?
            }
            SendSession::PollingForProposal(context) => {
                let mut relay_session =
                    RelaySession::new(self.sender_relay_plan(&context.endpoint())?);
                self.get_proposed_payjoin_psbt(context, persister, &mut relay_session).await?
            }
            SendSession::Closed(SenderSessionOutcome::Success(proposal)) => {
                self.process_pj_response(proposal)?;
                return Ok(());
            }
            SendSession::Closed(SenderSessionOutcome::Failure)
            | SendSession::Closed(SenderSessionOutcome::Cancel) => {
                let id = persister.session_id();
                println!(
                    "Session {id} ended without payjoin. Run `payjoin-cli fallback {id}` to broadcast the original transaction."
                );
                return Ok(());
            }
        }
        Ok(())
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        persister: &SenderPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let (response, ctx) = self
            .post_with_relay_session(relay_session, |relay| {
                sender.create_v2_post_request(relay.as_str()).map_err(Into::into)
            })
            .await?;
        let sender = sender.process_response(&response.bytes().await?, ctx).save(persister)?;
        println!("Posted Original PSBT...");
        self.get_proposed_payjoin_psbt(sender, persister, relay_session).await
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<PollingForProposal>,
        persister: &SenderPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let mut session = sender.clone();
        // Long poll until we get a response
        loop {
            let (response, ctx) = self
                .post_with_relay_session(relay_session, |relay| {
                    session.create_poll_request(relay.as_str()).map_err(Into::into)
                })
                .await?;
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
        relay_session: &mut RelaySession,
    ) -> Result<Receiver<UncheckedOriginalPayload>> {
        let mut session = session;
        loop {
            let (ohttp_response, context) = self
                .post_with_relay_session(relay_session, |relay| {
                    session.create_poll_request(relay.as_str()).map_err(Into::into)
                })
                .await?;
            println!("Polling receive request...");
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
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let res = {
            match session {
                ReceiveSession::Initialized(proposal) =>
                    self.read_from_directory(proposal, persister, relay_session).await,
                ReceiveSession::UncheckedOriginalPayload(proposal) =>
                    self.check_proposal(proposal, persister, relay_session).await,
                ReceiveSession::MaybeInputsOwned(proposal) =>
                    self.check_inputs_not_owned(proposal, persister, relay_session).await,
                ReceiveSession::MaybeInputsSeen(proposal) =>
                    self.check_no_inputs_seen_before(proposal, persister, relay_session).await,
                ReceiveSession::OutputsUnknown(proposal) =>
                    self.identify_receiver_outputs(proposal, persister, relay_session).await,
                ReceiveSession::WantsOutputs(proposal) =>
                    self.commit_outputs(proposal, persister, relay_session).await,
                ReceiveSession::WantsInputs(proposal) =>
                    self.contribute_inputs(proposal, persister, relay_session).await,
                ReceiveSession::WantsFeeRange(proposal) =>
                    self.apply_fee_range(proposal, persister, relay_session).await,
                ReceiveSession::ProvisionalProposal(proposal) =>
                    self.finalize_proposal(proposal, persister, relay_session).await,
                ReceiveSession::PayjoinProposal(proposal) =>
                    self.send_payjoin_proposal(proposal, persister, relay_session).await,
                ReceiveSession::HasReplyableError(error) =>
                    self.handle_error(error, persister, relay_session).await,
                ReceiveSession::Monitor(proposal) =>
                    self.monitor_payjoin_proposal(proposal, persister).await,
                ReceiveSession::Closed(_) => return Err(anyhow!("Session closed")),
            }
        };
        res
    }

    #[allow(clippy::incompatible_msrv)]
    async fn read_from_directory(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(session, persister, relay_session) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;
        self.check_proposal(receiver, persister, relay_session).await
    }

    async fn check_proposal(
        &self,
        proposal: Receiver<UncheckedOriginalPayload>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
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
        self.check_inputs_not_owned(proposal, persister, relay_session).await
    }

    async fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_inputs_not_owned(&mut |input| {
                wallet
                    .is_mine(input)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.check_no_inputs_seen_before(proposal, persister, relay_session).await
    }

    async fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let proposal = proposal
            .check_no_inputs_seen_before(&mut |input| {
                Ok(self.db.insert_input_seen_before(*input)?)
            })
            .save(persister)?;
        self.identify_receiver_outputs(proposal, persister, relay_session).await
    }

    async fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .identify_receiver_outputs(&mut |output_script| {
                wallet
                    .is_mine(output_script)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.commit_outputs(proposal, persister, relay_session).await
    }

    async fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let proposal = proposal.commit_outputs().save(persister)?;
        self.contribute_inputs(proposal, persister, relay_session).await
    }

    async fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let wallet = self.wallet();
        let candidate_inputs = wallet.list_unspent()?;

        if candidate_inputs.is_empty() {
            return Err(anyhow::anyhow!(
                "No spendable UTXOs available in wallet. Cannot contribute inputs to payjoin."
            ));
        }

        let selected_input = proposal.try_preserving_privacy(candidate_inputs)?;
        let proposal =
            proposal.contribute_inputs(vec![selected_input])?.commit_inputs().save(persister)?;
        self.apply_fee_range(proposal, persister, relay_session).await
    }

    async fn apply_fee_range(
        &self,
        proposal: Receiver<WantsFeeRange>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let proposal = proposal.apply_fee_range(None, self.config.max_fee_rate).save(persister)?;
        self.finalize_proposal(proposal, persister, relay_session).await
    }

    async fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let wallet = self.wallet();
        let proposal = proposal
            .finalize_proposal(|psbt| {
                wallet
                    .process_psbt(psbt)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        self.send_payjoin_proposal(proposal, persister, relay_session).await
    }

    async fn send_payjoin_proposal(
        &self,
        proposal: Receiver<PayjoinProposal>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let (res, ohttp_ctx) = self
            .post_with_relay_session(relay_session, |relay| {
                proposal
                    .create_post_request(relay.as_str())
                    .map_err(|e| anyhow!("v2 req extraction failed {}", e))
            })
            .await?;
        let payjoin_psbt = proposal.psbt().clone();
        let session = proposal.process_response(&res.bytes().await?, ohttp_ctx).save(persister)?;
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().compute_txid()
        );

        return self.monitor_payjoin_proposal(session, persister).await;
    }

    async fn monitor_payjoin_proposal(
        &self,
        proposal: Receiver<Monitor>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        // On a session resumption, the receiver will resume again in this state.
        let poll_interval = tokio::time::Duration::from_millis(200);
        let timeout_duration = tokio::time::Duration::from_secs(5);

        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await;

        tracing::debug!("Polling for payment confirmation");

        let result = tokio::time::timeout(timeout_duration, async {
            loop {
                interval.tick().await;
                let check_result = proposal
                    .check_payment(|txid| {
                        self.wallet()
                            .get_raw_transaction(&txid)
                            .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
                    })
                    .save(persister);

                match check_result {
                    Ok(_) => {
                        println!("Payjoin transaction detected in the mempool!");
                        return Ok(());
                    }
                    Err(_) => {
                        // keep polling

                        continue;
                    }
                }
            }
        })
        .await;

        match result {
            Ok(ok) => ok,
            Err(_) => Err(anyhow!(
                "Timeout waiting for payment confirmation after {:?}",
                timeout_duration
            )),
        }
    }

    fn sender_relay_plan(&self, endpoint: &str) -> Result<relay_selection::RelayPlan> {
        relay_selection::relay_plan_from_endpoint(
            self.config.v2()?,
            endpoint,
            relay_selection::RelayRole::Sender,
        )
    }

    fn receiver_relay_plan(&self, endpoint: &str) -> Result<relay_selection::RelayPlan> {
        relay_selection::relay_plan_from_endpoint(
            self.config.v2()?,
            endpoint,
            relay_selection::RelayRole::Receiver,
        )
    }

    async fn post_with_relay_session<Ctx, F>(
        &self,
        relay_session: &mut RelaySession,
        mut build_request: F,
    ) -> Result<(reqwest::Response, Ctx)>
    where
        F: FnMut(&payjoin::Url) -> Result<(payjoin::Request, Ctx)>,
    {
        let relay = relay_session.current_relay()?;
        let (req, ctx) = build_request(&relay.url)?;
        let response = self.post_request(req, &relay).await.map_err(|error| match error {
            RelayAttemptError::Retryable(error) | RelayAttemptError::Terminal(error) => error,
        })?;
        Ok((response, ctx))
    }

    /// Handle error by attempting to send an error response over the directory
    async fn handle_error(
        &self,
        session: Receiver<HasReplyableError>,
        persister: &ReceiverPersister,
        relay_session: &mut RelaySession,
    ) -> Result<()> {
        let (err_response, err_ctx) = self
            .post_with_relay_session(relay_session, |relay| {
                session.create_error_request(relay.as_str()).map_err(Into::into)
            })
            .await
            .map_err(|e| anyhow!("Failed to post error request: {e}"))?;

        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(anyhow!("Failed to get error response bytes: {}", e)),
        };

        if let Err(e) = session.process_error_response(&err_bytes, err_ctx).save(persister) {
            return Err(anyhow!("Failed to process error response: {}", e));
        }

        Ok(())
    }

    async fn post_request(
        &self,
        req: payjoin::Request,
        relay: &relay_selection::PinnedUrl,
    ) -> std::result::Result<reqwest::Response, RelayAttemptError> {
        let mut builder = http_client_builder(&self.config).map_err(|err| {
            RelayAttemptError::Terminal(anyhow!("Failed to build HTTP client: {err}"))
        })?;
        if let Some(domain) = relay.domain() {
            builder = builder.resolve_to_addrs(domain, &relay.socket_addrs);
        }
        let http = builder.build().map_err(|err| {
            RelayAttemptError::Terminal(anyhow!("Failed to build HTTP client: {err}"))
        })?;
        let response = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .map_err(|err| classify_reqwest_error(err, "HTTP request failed"))?;

        response
            .error_for_status()
            .map_err(|err| classify_reqwest_error(err, "HTTP request failed"))
    }
}
