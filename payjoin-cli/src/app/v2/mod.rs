use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate, Transaction};
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::receive::v2::{
    replay_event_log as replay_receiver_event_log, HasReplyableError, Initialized,
    MaybeInputsOwned, MaybeInputsSeen, Monitor, OutputsUnknown, PayjoinProposal,
    PendingFallback as ReceiverPendingFallback, ProvisionalProposal, ReceiveSession, Receiver,
    ReceiverBuilder, SessionOutcome as ReceiverSessionOutcome, UncheckedOriginalPayload,
    WantsFeeRange, WantsInputs, WantsOutputs,
};
use payjoin::send::v2::{
    replay_event_log as replay_sender_event_log, PendingFallback as SenderPendingFallback,
    PollingForProposal, SendSession, Sender, SenderBuilder, SessionOutcome as SenderSessionOutcome,
    WithReplyKey,
};
use payjoin::{ImplementationError, PjParam, Uri};
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
use crate::app::v2::ohttp::MailroomManager;
use crate::app::{handle_interrupt, http_agent};
use crate::cli::Role as CliRole;
use crate::db::v2::{ReceiverPersister, SenderPersister, SessionId};
use crate::db::Database;

mod ohttp;

const W_ID: usize = 36;
const W_ROLE: usize = 15;
const W_STATUS: usize = 15;

/// Delay before retrying a transiently failed state transition, so a
/// misbehaving directory or relay is not hammered in a tight loop.
const TRANSIENT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// A request-construction error that can report whether it was caused by
/// session expiry. Implemented by the sender/receiver request-building error
/// types so `post_via_relay` can hand expiry back to the caller (which owns the
/// typestate needed to react) instead of flattening it into `anyhow::Error`.
trait RequestExpiry {
    fn expired(&self) -> bool;
}

impl RequestExpiry for payjoin::send::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

impl RequestExpiry for payjoin::receive::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

/// Outcome of building and posting a request via `post_via_relay`. HTTP
/// failures are retried against other relays inside the helper; only session
/// expiry and fatal build errors escape to the caller.
enum RelayPost<T> {
    Posted(reqwest::Response, T),
    Expired,
}

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
    mailroom_manager: MailroomManager,
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
                SenderSessionOutcome::Aborted => "Session aborted",
                SenderSessionOutcome::Success(_) => "Session success",
            },
            SendSession::PendingFallback(_) => "Session awaiting fallback",
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
            ReceiveSession::PendingFallback(_) => "Pending fallback handling",
            ReceiveSession::Closed(session_outcome) => match session_outcome {
                ReceiverSessionOutcome::Aborted => "Session aborted",
                ReceiverSessionOutcome::Success(_) => "Session success, Payjoin proposal was broadcasted",
                ReceiverSessionOutcome::FallbackBroadcasted => "Fallback broadcasted",
                ReceiverSessionOutcome::PayjoinProposalSent =>
                    "Payjoin proposal sent, skipping monitoring as the sender is spending non-SegWit inputs",
                ReceiverSessionOutcome::Unrecognized(_) =>
                    "Settled by an unrecognized transaction",
            },
        }
    }
}

fn print_header() {
    println!("{:<W_ID$} {:<W_ROLE$} {:<W_STATUS$}", "Session ID", "Sender/Receiver", "Status");
}

#[derive(Clone, Copy)]
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

/// Print a session-scoped message prefixed with `[<Role> <session id>]`,
/// with the role padded so sender and receiver messages align in columns.
/// The prefix lets output interleaved from concurrently resumed sessions be
/// attributed to its session.
fn print_session(role: Role, id: &SessionId, msg: impl fmt::Display) {
    // Pad the role to the widest form, `Receiver`.
    const W: usize = "Receiver".len();
    println!("[{:<W$} {id}] {msg}", role.as_str());
}

/// Session-scoped printing: the persister carries the role and session id
/// that every user-facing message must be attributed to.
trait SessionPrint {
    fn print(&self, msg: impl fmt::Display);
}

impl SessionPrint for SenderPersister {
    fn print(&self, msg: impl fmt::Display) {
        print_session(Role::Sender, &self.session_id(), msg);
    }
}

impl SessionPrint for ReceiverPersister {
    fn print(&self, msg: impl fmt::Display) {
        print_session(Role::Receiver, &self.session_id(), msg);
    }
}

struct SessionHistoryRow<Status> {
    session_id: SessionId,
    role: Role,
    status: Status,
    error_message: Option<String>,
    fallback_available: bool,
}

impl<Status: StatusText> fmt::Display for SessionHistoryRow<Status> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_text = match (self.error_message.as_deref(), self.fallback_available) {
            (Some(err), _) => err.to_string(),
            (None, true) =>
                format!("{}, Fallback transaction available", self.status.status_text()),
            (None, false) => self.status.status_text().to_string(),
        };
        write!(
            f,
            "{:<W_ID$} {:<W_ROLE$} {:<W_STATUS$}",
            self.session_id.to_string(),
            self.role.as_str(),
            status_text
        )
    }
}

#[async_trait::async_trait]
impl AppTrait for App {
    async fn new(config: Config) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let mailroom_manager = MailroomManager::new(config.clone());
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind).await?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx, mailroom_manager };
        app.wallet()
            .network()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn wallet(&self) -> BitcoindWallet { self.wallet.clone() }

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

                let txid = self.process_pj_response(psbt)?;
                println!("Payjoin sent. TXID: {txid}");
                Ok(())
            }
            PjParam::V2(pj_param) => {
                let receiver_pubkey = pj_param.receiver_pubkey();
                let sender_state = self
                    .db
                    .get_send_session_id_by_receiver_pk(receiver_pubkey)?
                    .and_then(|session_id| {
                        let sender_persister =
                            SenderPersister::from_id(self.db.clone(), session_id);
                        let (send_session, _) = replay_sender_event_log(&sender_persister)
                            .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))
                            .ok()?;
                        Some((send_session, sender_persister))
                    });

                let (sender_state, persister) = match sender_state {
                    Some((sender_state, persister)) => (sender_state, persister),
                    None => {
                        let psbt = self.create_original_psbt(&address, amount, fee_rate)?;
                        let persister =
                            SenderPersister::new(self.db.clone(), bip21, receiver_pubkey)?;
                        persister.print("Session established");
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
                                persister.print(format_args!("Session failed. Run `payjoin-cli cancel {id}` to cancel and broadcast the original transaction."));
                                return Err(err);
                            }
                        }
                    },
                    _ = interrupt.changed() => {
                        let session_id = persister.session_id();
                        persister.print(format_args!(
                            "Session interrupted. Call `payjoin-cli resume --session-id {session_id}` again to resume, `payjoin-cli resume` to resume all sessions, or `payjoin-cli cancel {session_id}` to cancel and broadcast the original transaction."
                        ));
                        return Err(anyhow!("Interrupted"))
                    }
                }
            }
            _ => unimplemented!("Unrecognized payjoin version"),
        }
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let address = self.wallet().get_new_address()?;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let (directory, ohttp_keys) = loop {
            let directory = self.mailroom_manager.choose_directory()?;
            match self
                .mailroom_manager
                .unwrap_ohttp_keys_or_else_fetch_from_directory(&directory)
                .await
            {
                Ok(keys) => break (directory, keys.ohttp_keys),
                Err(e) => {
                    tracing::debug!("Directory {directory} failed: {e:#}");
                    self.mailroom_manager.add_failed_directory(directory);
                    self.mailroom_manager.clear_failed_relays();
                    continue;
                }
            }
        };
        let mut receiver_builder =
            ReceiverBuilder::new(address, directory.as_str(), ohttp_keys)?.with_amount(amount);
        if let Some(max_fee_rate) = self.config.max_fee_rate {
            receiver_builder = receiver_builder.with_max_fee_rate(max_fee_rate);
        }
        if let Some(expire_in_secs) = self.config.expire_in_secs {
            let expiration = std::time::Duration::from_secs(expire_in_secs);
            receiver_builder = receiver_builder.with_expiration(expiration);
        }
        let session = receiver_builder.build().save(&persister)?;
        persister.print("Session established");

        let pj_uri = session.pj_uri();
        persister.print("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        // Interrupting is safe at any phase: every transition is saved to the
        // event log before the next await, so the session resumes from its
        // last saved state via the resume command.
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.process_receiver_session(
                ReceiveSession::Initialized(session.clone()),
                &persister,
            ) => res?,
            _ = interrupt.changed() => {
                let session_id = persister.session_id();
                persister.print(format_args!(
                    "Session interrupted. Call `payjoin-cli resume --session-id {session_id}` again to resume, `payjoin-cli resume` to resume all sessions, or `payjoin-cli cancel {session_id}` to cancel the session."
                ));
                return Err(anyhow!("Interrupted"));
            }
        }
        Ok(())
    }

    async fn resume_payjoins(&self, session_id: Option<SessionId>) -> Result<()> {
        let mut recv_session_ids = self.db.get_recv_session_ids()?;
        let mut send_session_ids = self.db.get_send_session_ids()?;

        if let Some(ref target_id) = session_id {
            recv_session_ids.retain(|id| id == target_id);
            send_session_ids.retain(|id| id == target_id);
            if recv_session_ids.is_empty() && send_session_ids.is_empty() {
                anyhow::bail!("Session {target_id} not found or already completed");
            }
        }

        if recv_session_ids.is_empty() && send_session_ids.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks: Vec<((Role, SessionId), tokio::task::JoinHandle<Result<()>>)> = Vec::new();

        // Process receiver sessions
        for session_id in recv_session_ids {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&recv_persister) {
                Ok((receiver_state, _)) => {
                    tasks.push((
                        (Role::Receiver, session_id),
                        tokio::spawn(async move {
                            self_clone
                                .process_receiver_session(receiver_state, &recv_persister)
                                .await
                        }),
                    ));
                }
                Err(e) if e.is_expired() => {
                    if let Err(err) = self.cancel_receiver_session(session_id.clone(), true) {
                        tracing::error!(
                            "Failed to cancel expired receiver session {session_id}: {err:?}"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying session", e);
                    recv_persister.print(format_args!("Session failed to replay: {e}"));
                    Self::close_failed_session(&recv_persister, &session_id, Role::Receiver);
                }
            }
        }

        // Process sender sessions
        for session_id in send_session_ids {
            let sender_persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&sender_persister) {
                Ok((sender_state, _)) => {
                    let self_clone = self.clone();
                    tasks.push((
                        (Role::Sender, session_id),
                        tokio::spawn(async move {
                            self_clone.process_sender_session(sender_state, &sender_persister).await
                        }),
                    ));
                }
                Err(e) if e.is_expired() => {
                    if let Err(err) = self.cancel_sender_session(session_id.clone(), true) {
                        tracing::error!(
                            "Failed to cancel expired sender session {session_id}: {err:?}"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("An error {:?} occurred while replaying session", e);
                    sender_persister.print(format_args!("Session failed to replay: {e}"));
                    Self::close_failed_session(&sender_persister, &session_id, Role::Sender);
                }
            }
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = async {

                for ((role, id), task) in tasks {
                    match task.await {
                        Ok(Ok(())) => {
                            print_session(role, &id, "Session completed.");
                        }
                        Ok(Err(e)) => {
                            print_session(role, &id, format_args!("Session error: {e:#}"));
                        }
                        Err(e) => {
                            print_session(role, &id, format_args!("Session panicked or was cancelled: {e:?}"));
                        }
                    }
                }
        } => {}
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
                Ok((sender_state, _session_history)) => {
                    let fallback_available =
                        matches!(sender_state, SendSession::Closed(SenderSessionOutcome::Aborted));
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: sender_state.clone(),
                        error_message: None,
                        fallback_available,
                    };
                    send_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: SendSession::Closed(SenderSessionOutcome::Aborted),
                        error_message: Some(e.to_string()),
                        fallback_available: false,
                    };
                    send_rows.push(row);
                }
            }
        });

        self.db.get_recv_session_ids()?.into_iter().for_each(|session_id| {
            let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&persister) {
                Ok((receiver_state, session_history)) => {
                    let fallback_available = matches!(
                        receiver_state,
                        ReceiveSession::Closed(ReceiverSessionOutcome::Aborted)
                    ) && session_history.fallback_tx().is_some();
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: receiver_state.clone(),
                        error_message: None,
                        fallback_available,
                    };
                    recv_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: ReceiveSession::Closed(ReceiverSessionOutcome::Aborted),
                        error_message: Some(e.to_string()),
                        fallback_available: false,
                    };
                    recv_rows.push(row);
                }
            }
        });

        self.db.get_inactive_send_session_ids()?.into_iter().for_each(|(session_id, _)| {
            let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
            match replay_sender_event_log(&persister) {
                Ok((sender_state, _)) => {
                    let fallback_available =
                        matches!(sender_state, SendSession::Closed(SenderSessionOutcome::Aborted));
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: sender_state.clone(),
                        error_message: None,
                        fallback_available,
                    };
                    send_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Sender,
                        status: SendSession::Closed(SenderSessionOutcome::Aborted),
                        error_message: Some(e.to_string()),
                        fallback_available: false,
                    };
                    send_rows.push(row);
                }
            }
        });

        self.db.get_inactive_recv_session_ids()?.into_iter().for_each(|(session_id, _)| {
            let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
            match replay_receiver_event_log(&persister) {
                Ok((receiver_state, session_history)) => {
                    let fallback_available = matches!(
                        receiver_state,
                        ReceiveSession::Closed(ReceiverSessionOutcome::Aborted)
                    ) && session_history.fallback_tx().is_some();
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: receiver_state.clone(),
                        error_message: None,
                        fallback_available,
                    };
                    recv_rows.push(row);
                }
                Err(e) => {
                    let row = SessionHistoryRow {
                        session_id,
                        role: Role::Receiver,
                        status: ReceiveSession::Closed(ReceiverSessionOutcome::Aborted),
                        error_message: Some(e.to_string()),
                        fallback_available: false,
                    };
                    recv_rows.push(row);
                }
            }
        });

        // Collect every row (active + inactive, sender + receiver), sort by
        // session id, and print in a single stable order regardless of which
        // table or active/inactive bucket the row came from.
        let mut rows: Vec<(SessionId, String)> = Vec::new();
        for row in send_rows {
            rows.push((row.session_id.clone(), format!("{row}")));
        }
        for row in recv_rows {
            rows.push((row.session_id.clone(), format!("{row}")));
        }
        rows.sort_by_key(|(id, _)| id.clone());
        for (_, line) in rows {
            println!("{line}");
        }

        Ok(())
    }

    async fn cancel(
        &self,
        session_id: SessionId,
        no_broadcast: bool,
        role: Option<CliRole>,
    ) -> Result<()> {
        if let Some(role) = role {
            return match role {
                CliRole::Sender => self.cancel_sender_session(session_id, no_broadcast),
                CliRole::Receiver => self.cancel_receiver_session(session_id, no_broadcast),
            };
        }

        let is_sender = self.db.send_session_exists(&session_id)?;
        let is_receiver = self.db.recv_session_exists(&session_id)?;

        match (is_sender, is_receiver) {
            (true, false) => self.cancel_sender_session(session_id, no_broadcast),
            (false, true) => self.cancel_receiver_session(session_id, no_broadcast),
            (true, true) => anyhow::bail!(
                "Session {session_id} exists as both a sender and receiver session. \
                 Pass `--role sender` or `--role receiver`."
            ),
            (false, false) => anyhow::bail!("Session {session_id} not found"),
        }
    }
}

impl App {
    fn cancel_sender_session(&self, session_id: SessionId, no_broadcast: bool) -> Result<()> {
        let persister = SenderPersister::from_id(self.db.clone(), session_id.clone());
        let (session, history) = match replay_sender_event_log(&persister) {
            Ok((session, history)) => (session, history),
            Err(e) if e.is_expired() => {
                Self::finalize_expired_session(
                    &persister,
                    &session_id,
                    Role::Sender,
                    e.expiry_fallback_tx(),
                );
                return Ok(());
            }
            Err(e) => return Err(anyhow!("Failed to replay sender session {session_id}: {:?}", e)),
        };

        let pending: Sender<SenderPendingFallback> = match session {
            SendSession::WithReplyKey(sender) => sender.cancel().save(&persister)?,
            SendSession::PollingForProposal(sender) => sender.cancel().save(&persister)?,
            SendSession::PendingFallback(sender) => sender,
            SendSession::Closed(SenderSessionOutcome::Success(proposal)) => {
                let txid = proposal.extract_tx_unchecked_fee_rate().compute_txid();
                persister.print(format_args!(
                    "Session already produced payjoin transaction {txid}. \
                     Cannot cancel a completed session."
                ));
                return Ok(());
            }
            SendSession::Closed(SenderSessionOutcome::Aborted) => {
                persister.print(
                    "Session was already cancelled. Broadcast the original transaction manually:",
                );
                println!("{}", serialize_hex(&history.fallback_tx()));
                return Ok(());
            }
        };

        if no_broadcast {
            persister.print("Session cancelled. Broadcast the original transaction manually:");
            println!("{}", serialize_hex(pending.fallback_tx()));
        } else {
            self.wallet().broadcast_tx(pending.fallback_tx())?;
            persister.print(format_args!(
                "Broadcasted fallback transaction txid: {}",
                pending.fallback_tx().compute_txid()
            ));
        }
        pending.close().save(&persister)?;
        Ok(())
    }

    fn cancel_receiver_session(&self, session_id: SessionId, no_broadcast: bool) -> Result<()> {
        let persister = ReceiverPersister::from_id(self.db.clone(), session_id.clone());
        let (session, history) = match replay_receiver_event_log(&persister) {
            Ok((session, history)) => (session, history),
            Err(e) if e.is_expired() => {
                Self::finalize_expired_session(
                    &persister,
                    &session_id,
                    Role::Receiver,
                    e.expiry_fallback_tx(),
                );
                return Ok(());
            }
            Err(e) =>
                return Err(anyhow!("Failed to replay receiver session {session_id}: {:?}", e)),
        };

        let pending: Receiver<ReceiverPendingFallback> = match session {
            ReceiveSession::Initialized(receiver) => {
                receiver.cancel().save(&persister)?;
                persister.print("Session cancelled. No fallback transaction to broadcast.");
                return Ok(());
            }
            ReceiveSession::UncheckedOriginalPayload(receiver) => {
                receiver.cancel().save(&persister)?;
                persister.print("Session cancelled. No fallback transaction to broadcast.");
                return Ok(());
            }
            ReceiveSession::MaybeInputsOwned(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::MaybeInputsSeen(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::OutputsUnknown(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::WantsOutputs(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::WantsInputs(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::WantsFeeRange(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::ProvisionalProposal(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::PayjoinProposal(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::Monitor(receiver) => receiver.cancel().save(&persister)?,
            ReceiveSession::HasReplyableError(receiver) =>
                match receiver.cancel().save(&persister)? {
                    Some(pending) => pending,
                    None => {
                        persister.print("Session cancelled. No fallback transaction available.");
                        return Ok(());
                    }
                },
            ReceiveSession::PendingFallback(receiver) => receiver,
            ReceiveSession::Closed(
                ReceiverSessionOutcome::Success(_)
                | ReceiverSessionOutcome::FallbackBroadcasted
                | ReceiverSessionOutcome::PayjoinProposalSent,
            ) => {
                persister.print("Session already completed successfully. Cannot cancel.");
                return Ok(());
            }
            ReceiveSession::Closed(ReceiverSessionOutcome::Aborted) => {
                match history.fallback_tx() {
                    Some(tx) => {
                        persister.print(
                            "Session was already cancelled. Broadcast the fallback transaction manually:",
                        );
                        println!("{}", serialize_hex(&tx));
                    }
                    None => persister
                        .print("Session is already closed. No fallback transaction available."),
                }
                return Ok(());
            }
            ReceiveSession::Closed(ReceiverSessionOutcome::Unrecognized(_)) => {
                persister.print(format_args!(
                    "Session was already closed by an unrecognized transaction. Cannot cancel."
                ));
                return Ok(());
            }
        };

        if no_broadcast {
            persister.print("Session cancelled. Broadcast the fallback transaction manually:");
            println!("{}", serialize_hex(pending.fallback_tx()));
        } else {
            self.wallet().broadcast_tx(pending.fallback_tx())?;
            persister.print(format_args!(
                "Broadcasted fallback transaction txid: {}",
                pending.fallback_tx().compute_txid()
            ));
        }
        pending.close().save(&persister)?;
        Ok(())
    }

    fn close_failed_session<P>(persister: &P, session_id: &SessionId, role: Role)
    where
        P: SessionPersister,
    {
        if let Err(close_err) = SessionPersister::close(persister) {
            tracing::error!(
                "Failed to close {} session {}: {:?}",
                role.as_str(),
                session_id,
                close_err
            );
        } else {
            tracing::debug!("Closed failed {} session: {}", role.as_str(), session_id);
        }
    }

    /// Report an expired session to the user, pointing at the fallback
    /// transaction from the event log if one exists, and close the session
    /// so it is not resumed again.
    fn finalize_expired_session<P>(
        persister: &P,
        session_id: &SessionId,
        role: Role,
        fallback_tx: Option<&Transaction>,
    ) where
        P: SessionPersister,
    {
        match fallback_tx {
            Some(tx) => {
                print_session(
                    role,
                    session_id,
                    "Session expired. Broadcast the original transaction manually:",
                );
                println!("{}", serialize_hex(tx));
            }
            None => print_session(
                role,
                session_id,
                "Session expired. No fallback transaction available.",
            ),
        }
        Self::close_failed_session(persister, session_id, role);
    }

    /// Drive the sender state machine until the session terminates. Each
    /// step function performs one state transition and returns the next
    /// state; the driver stops on the terminal `Closed` and
    /// `PendingFallback` states.
    async fn process_sender_session(
        &self,
        mut session: SendSession,
        persister: &SenderPersister,
    ) -> Result<()> {
        loop {
            session = match session {
                SendSession::WithReplyKey(context) =>
                    self.post_original_proposal(context, persister).await?,
                SendSession::PollingForProposal(context) =>
                    self.get_proposed_payjoin_psbt(context, persister).await?,
                SendSession::Closed(SenderSessionOutcome::Success(proposal)) => {
                    let txid = self.process_pj_response(proposal)?;
                    persister.print(format_args!("Payjoin sent. TXID: {txid}"));
                    return Ok(());
                }
                SendSession::Closed(SenderSessionOutcome::Aborted) => return Ok(()),
                SendSession::PendingFallback(_) => {
                    let id = persister.session_id();
                    persister.print(format_args!(
                        "Session was cancelled. Run `payjoin-cli cancel {id}` to cancel and broadcast the fallback transaction."
                    ));
                    return Ok(());
                }
            };
        }
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        persister: &SenderPersister,
    ) -> Result<SendSession> {
        let (response, ctx) =
            match self.post_via_relay(|relay| sender.create_v2_post_request(relay)).await? {
                RelayPost::Posted(resp, ctx) => (resp, ctx),
                RelayPost::Expired => {
                    self.cancel_sender_session(persister.session_id(), true)?;
                    return Ok(SendSession::Closed(SenderSessionOutcome::Aborted));
                }
            };
        match sender.process_response(&response.bytes().await?, ctx).save(persister) {
            Ok(sender) => {
                persister.print("Posted Original PSBT...");
                Ok(SendSession::PollingForProposal(sender))
            }
            Err(e) if e.is_transient() => {
                tracing::debug!("Transient error posting original proposal, retrying: {e:?}");
                let sender = e.transient_state().expect("transient error carries current state");
                tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                Ok(SendSession::WithReplyKey(sender))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<PollingForProposal>,
        persister: &SenderPersister,
    ) -> Result<SendSession> {
        let (response, ctx) =
            match self.post_via_relay(|relay| sender.create_poll_request(relay)).await? {
                RelayPost::Posted(resp, ctx) => (resp, ctx),
                RelayPost::Expired => {
                    self.cancel_sender_session(persister.session_id(), true)?;
                    return Ok(SendSession::Closed(SenderSessionOutcome::Aborted));
                }
            };
        let res = sender.clone().process_response(&response.bytes().await?, ctx).save(persister);
        match res {
            Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                persister.print("Proposal received. Processing...");
                Ok(SendSession::Closed(SenderSessionOutcome::Success(psbt)))
            }
            Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                persister.print("No response yet.");
                Ok(SendSession::PollingForProposal(current_state))
            }
            Err(e) if e.is_transient() => {
                tracing::debug!("Transient error polling for proposal, retrying: {e:?}");
                let sender = e.transient_state().expect("transient error carries current state");
                tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                Ok(SendSession::PollingForProposal(sender))
            }
            Err(re) => {
                persister.print(&re);
                tracing::debug!("{re:?}");
                Err(anyhow!("Response error").context(re))
            }
        }
    }

    /// Drive the receiver state machine until the session terminates. Each
    /// step function performs one state transition and returns the next
    /// state; the driver stops on the terminal `Closed` and
    /// `PendingFallback` states.
    async fn process_receiver_session(
        &self,
        mut session: ReceiveSession,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        loop {
            session = match session {
                ReceiveSession::Initialized(proposal) =>
                    self.read_from_directory(proposal, persister).await?,
                ReceiveSession::UncheckedOriginalPayload(proposal) =>
                    self.check_proposal(proposal, persister)?,
                ReceiveSession::MaybeInputsOwned(proposal) =>
                    self.check_inputs_not_owned(proposal, persister)?,
                ReceiveSession::MaybeInputsSeen(proposal) =>
                    self.check_no_inputs_seen_before(proposal, persister)?,
                ReceiveSession::OutputsUnknown(proposal) =>
                    self.identify_receiver_outputs(proposal, persister)?,
                ReceiveSession::WantsOutputs(proposal) =>
                    self.commit_outputs(proposal, persister)?,
                ReceiveSession::WantsInputs(proposal) =>
                    self.contribute_inputs(proposal, persister)?,
                ReceiveSession::WantsFeeRange(proposal) =>
                    self.apply_fee_range(proposal, persister)?,
                ReceiveSession::ProvisionalProposal(proposal) =>
                    self.finalize_proposal(proposal, persister)?,
                ReceiveSession::PayjoinProposal(proposal) =>
                    self.send_payjoin_proposal(proposal, persister).await?,
                ReceiveSession::HasReplyableError(error) =>
                    self.handle_error(error, persister).await?,
                ReceiveSession::Monitor(proposal) => {
                    self.monitor_payjoin_proposal(proposal, persister).await?;
                    return Ok(());
                }
                ReceiveSession::PendingFallback(_) => {
                    let id = persister.session_id();
                    persister.print(format_args!(
                        "Session was cancelled. Run `payjoin-cli cancel {id}` to cancel and broadcast the fallback transaction."
                    ));
                    return Ok(());
                }
                ReceiveSession::Closed(_) => return Ok(()),
            };
        }
    }

    /// Poll the directory once for the sender's original proposal.
    async fn read_from_directory(
        &self,
        session: Receiver<Initialized>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        persister.print("Polling receive request...");
        let (ohttp_response, context) =
            match self.post_via_relay(|relay| session.create_poll_request(relay)).await? {
                RelayPost::Posted(resp, ctx) => (resp, ctx),
                RelayPost::Expired => {
                    self.cancel_receiver_session(persister.session_id(), true)?;
                    return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
                }
            };
        let state_transition = session
            .process_response(ohttp_response.bytes().await?.to_vec().as_slice(), context)
            .save(persister);
        match state_transition {
            Ok(OptionalTransitionOutcome::Progress(next_state)) => {
                persister
                    .print("Got a request from the sender. Responding with a Payjoin proposal.");
                Ok(ReceiveSession::UncheckedOriginalPayload(next_state))
            }
            Ok(OptionalTransitionOutcome::Stasis(current_state)) =>
                Ok(ReceiveSession::Initialized(current_state)),
            Err(e) if e.is_transient() => {
                tracing::debug!("Transient error polling for request, retrying: {e:?}");
                let session = e.transient_state().expect("transient error carries current state");
                tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                Ok(ReceiveSession::Initialized(session))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn check_proposal(
        &self,
        proposal: Receiver<UncheckedOriginalPayload>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_broadcast_suitability(None, |tx| {
                wallet
                    .can_broadcast(tx)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;

        persister.print(
            "Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:",
        );
        println!("{}", serialize_hex(&proposal.extract_tx_to_schedule_broadcast()));
        Ok(ReceiveSession::MaybeInputsOwned(proposal))
    }

    fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_inputs_not_owned(&mut |input| {
                wallet
                    .is_mine(input)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        Ok(ReceiveSession::MaybeInputsSeen(proposal))
    }

    fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let proposal = proposal
            .check_no_inputs_seen_before(&mut |input| {
                Ok(self.db.insert_input_seen_before(*input)?)
            })
            .save(persister)?;
        Ok(ReceiveSession::OutputsUnknown(proposal))
    }

    fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let wallet = self.wallet();
        let proposal = proposal
            .identify_receiver_outputs(&mut |output_script| {
                wallet
                    .is_mine(output_script)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        Ok(ReceiveSession::WantsOutputs(proposal))
    }

    fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let proposal = proposal.commit_outputs().save(persister)?;
        Ok(ReceiveSession::WantsInputs(proposal))
    }

    fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
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
        Ok(ReceiveSession::WantsFeeRange(proposal))
    }

    fn apply_fee_range(
        &self,
        proposal: Receiver<WantsFeeRange>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let proposal = proposal.apply_fee_range(None, self.config.max_fee_rate).save(persister)?;
        Ok(ReceiveSession::ProvisionalProposal(proposal))
    }

    fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let wallet = self.wallet();
        let proposal = proposal
            .finalize_proposal(|psbt| {
                wallet
                    .process_psbt(psbt)
                    .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
            })
            .save(persister)?;
        Ok(ReceiveSession::PayjoinProposal(proposal))
    }

    async fn send_payjoin_proposal(
        &self,
        proposal: Receiver<PayjoinProposal>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let (res, ohttp_ctx) =
            match self.post_via_relay(|relay| proposal.create_post_request(relay)).await? {
                RelayPost::Posted(resp, ctx) => (resp, ctx),
                RelayPost::Expired => {
                    self.cancel_receiver_session(persister.session_id(), true)?;
                    return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
                }
            };
        let payjoin_psbt = proposal.psbt().clone();
        match proposal.process_response(&res.bytes().await?, ohttp_ctx).save(persister) {
            Ok(session) => {
                persister.print(format_args!(
                    "Response successful. Watch mempool for successful Payjoin. TXID: {}",
                    payjoin_psbt.extract_tx_unchecked_fee_rate().compute_txid()
                ));
                Ok(ReceiveSession::Monitor(session))
            }
            Err(e) if e.is_transient() => {
                tracing::debug!("Transient error sending payjoin proposal, retrying: {e:?}");
                let proposal = e.transient_state().expect("transient error carries current state");
                tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                Ok(ReceiveSession::PayjoinProposal(proposal))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Watch the mempool for the payjoin transaction until it appears or a
    /// timeout elapses. The poll/timeout loop is one logical step from the
    /// session's perspective, so it stays local rather than in the driver.
    async fn monitor_payjoin_proposal(
        &self,
        mut proposal: Receiver<Monitor>,
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
                    .check_for_transaction(|txid| {
                        self.wallet()
                            .get_raw_transaction(&txid)
                            .map_err(|e| ImplementationError::from(e.into_boxed_dyn_error()))
                    })
                    .save(persister);

                match check_result {
                    Ok(OptionalTransitionOutcome::Progress(())) => {
                        persister.print("Payjoin transaction detected in the mempool!");
                        return Ok(());
                    }
                    Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                        proposal = current_state;
                    }
                    Err(e) if e.is_transient() => {
                        tracing::debug!(
                            "Transient error checking for transaction, retrying: {e:?}"
                        );
                        proposal =
                            e.transient_state().expect("transient error carries current state");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await;

        match result {
            Ok(ok) => ok,
            Err(_) => Err(anyhow!(
                "No payjoin transaction detected in mempool within {timeout_duration:?}, stopping."
            )),
        }
    }

    /// Handle error by attempting to send an error response over the directory
    async fn handle_error(
        &self,
        session: Receiver<HasReplyableError>,
        persister: &ReceiverPersister,
    ) -> Result<ReceiveSession> {
        let (err_response, err_ctx) =
            match self.post_via_relay(|relay| session.create_error_request(relay)).await? {
                RelayPost::Posted(resp, ctx) => (resp, ctx),
                RelayPost::Expired => {
                    self.cancel_receiver_session(persister.session_id(), true)?;
                    return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
                }
            };
        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(anyhow!("Failed to get error response bytes: {}", e)),
        };

        match session.process_error_response(&err_bytes, err_ctx).save(persister) {
            Ok(Some(pending)) => {
                persister.print(
                    "Session delivered error reply. Broadcast the fallback transaction manually:",
                );
                println!("{}", serialize_hex(pending.fallback_tx()));
                Ok(ReceiveSession::PendingFallback(pending))
            }
            Ok(None) => Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted)),
            Err(e) if e.is_transient() => {
                tracing::debug!("Transient error posting error response, retrying: {e:?}");
                let session = e.transient_state().expect("transient error carries current state");
                tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                Ok(ReceiveSession::HasReplyableError(session))
            }
            Err(e) => {
                if let Some(api_err) = e.api_error_ref() {
                    tracing::warn!("Failed to confirm error response delivery: {api_err}");
                }
                match e.fatal_state() {
                    Some(pending) => {
                        persister.print(
                            "Session failed to deliver error reply. Broadcast the fallback transaction manually:",
                        );
                        println!("{}", serialize_hex(pending.fallback_tx()));
                        Ok(ReceiveSession::PendingFallback(pending))
                    }
                    None => Err(anyhow!("Failed to process error response")),
                }
            }
        }
    }

    async fn post_request(&self, req: payjoin::Request) -> Result<reqwest::Response> {
        let http = http_agent(&self.config)?;
        http.post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .context("HTTP request failed")
    }

    async fn post_via_relay<F, T, E>(&self, mut build: F) -> Result<RelayPost<T>>
    where
        F: FnMut(&str) -> std::result::Result<(payjoin::Request, T), E>,
        E: RequestExpiry + Into<anyhow::Error>,
    {
        loop {
            let relay = self.mailroom_manager.choose_relay()?;
            let (req, ctx) = match build(relay.as_str()) {
                Ok(r) => r,
                Err(e) if e.expired() => return Ok(RelayPost::Expired),
                Err(e) => return Err(e.into()),
            };
            match self.post_request(req).await {
                Ok(resp) => return Ok(RelayPost::Posted(resp, ctx)),
                Err(e) => {
                    tracing::debug!("Request to relay {relay} failed: {e:?}");
                    self.mailroom_manager.add_failed_relay(relay);
                }
            }
        }
    }
}
