use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures::future::{self, FutureExt};
use payjoin::directory::ShortId;
use tokio::sync::{oneshot, RwLock};
use tokio::time::Instant;
use tracing::trace;

#[cfg(test)]
/// set an artificially low capacity for testing to ensure coverage of pruning code
const DEFAULT_CAPACITY: usize = 2;

#[cfg(not(test))]
/// The maximum number of pending or populated mailbox entries.
///
/// Defaults to around 2e6, for a generous upper bound rounded up from ~2
/// mailboxes/tx, ~4K txs/block, and ~144 blocks/24h.
const DEFAULT_CAPACITY: usize = 1 << (1 + 12 + 8);

const UNREAD_TTL_AT_CAPACITY: Duration = Duration::from_secs(60 * 60 * 24); // 24 HRS
const UNREAD_TTL_BELOW_CAPACITY: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 1 week

#[cfg(test)]
const READ_TTL: Duration = Duration::from_millis(1);
#[cfg(not(test))]
/// How long read messages should be kept in mailboxes. Defaults to a 10 minute
/// grace period from first read attempt, incase of intermittent network or
/// relay errors.
const READ_TTL: Duration = Duration::from_secs(60 * 10);

#[derive(Debug)]
struct MailboxContents {
    metadata: Metadata,
    payload: Arc<Vec<u8>>,
}

impl MailboxContents {
    fn mark_read(&mut self) { self.metadata.read = Some(Instant::now()) }
}

#[derive(Debug, Eq, PartialEq)]
struct Metadata {
    read: Option<Instant>,
    created: Instant,
}

impl Ord for Metadata {
    /// Reverse ordering by expires for min-heap semantics
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        std::cmp::Reverse(self.read)
            .cmp(&std::cmp::Reverse(other.read))
            .then(std::cmp::Reverse(self.created).cmp(&std::cmp::Reverse(other.created)))
    }
}

impl PartialOrd for Metadata {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

#[derive(Debug)]
struct V2WaitMapEntry {
    receiver: future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>,
    sender: oneshot::Sender<Arc<Vec<u8>>>, // TODO [u8; 7168]
}

// WaitMap
#[derive(Debug)]
pub(crate) struct Mailboxes {
    timeout: Duration,
    capacity: usize,
    populated: HashMap<ShortId, MailboxContents>,
    pending_v1: HashMap<ShortId, oneshot::Sender<Vec<u8>>>,
    pending_v2: HashMap<ShortId, V2WaitMapEntry>,
    read_order: VecDeque<ShortId>,
    insert_order: VecDeque<ShortId>,
}

impl Mailboxes {
    fn new(timeout: Duration) -> Self { Self { timeout, ..Self::default() } }
}

impl Default for Mailboxes {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            capacity: DEFAULT_CAPACITY,
            populated: HashMap::default(),
            pending_v1: HashMap::default(),
            pending_v2: HashMap::default(),
            read_order: VecDeque::default(),
            insert_order: VecDeque::default(),
        }
    }
}

#[derive(Clone)]
pub struct Db(Arc<RwLock<Mailboxes>>);

impl Db {
    pub fn new(timeout: Duration) -> Self { Self(Arc::new(RwLock::new(Mailboxes::new(timeout)))) }
}

impl Mailboxes {
    fn get(&mut self, id: &ShortId) -> Option<Arc<Vec<u8>>> {
        let mut ret = None;

        self.populated.entry(*id).and_modify(|entry| {
            // if the entry exists and hasn't been read, mark it read
            if !entry.metadata.read.is_none() {
                entry.mark_read();
                self.read_order.push_back(*id);
            }

            // and return a shared ref to the payload
            ret = Some(entry.payload.clone());
        });

        ret
    }
    fn has_capacity(&mut self) -> bool {
        self.prune();
        self.len() < self.capacity
    }

    fn can_wait_for_mailbox(&mut self, id: &ShortId) -> Result<(), Error> {
        debug_assert!(
            !self.populated.contains_key(id),
            "should not be called when an entry already exists"
        );

        self.check_invariants();

        if !self.has_capacity() {
            // avoid leaking information about whether there's an in flight
            // request under this ID and whether it's read
            return Err(Error::OverCapacity);
        }

        // Check that there isn't there's already a v1 waiter for this ID, can't
        // accept write needs to be rejected
        if self.pending_v1.contains_key(id) {
            return Err(Error::OverCapacity);
        }

        Ok(())
    }

    fn wait_v2(
        &mut self,
        id: &ShortId,
    ) -> Result<future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>, Error> {
        self.can_wait_for_mailbox(id)?;

        let receiver = self
            .pending_v2
            .entry(*id)
            .or_insert_with(|| {
                let (sender, receiver) = oneshot::channel::<Arc<Vec<u8>>>();
                let shared_receiver = receiver.shared();
                V2WaitMapEntry { sender, receiver: shared_receiver.clone() }
            })
            .receiver
            .clone();

        self.check_invariants();

        Ok(receiver)
    }

    fn post_v2(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<(), Error> {
        // TODO forbid overwriting? currently relied on by ns1r
        // if self.populated.contains_key(id) {
        //     return None;
        // }

        self.check_invariants();

        let mut contents = MailboxContents {
            metadata: Metadata { read: None, created: Instant::now() },
            payload: Arc::new(payload),
        };

        // If there are pending readers, satisfy them and mark the payload as read
        if let Some(pending) = self.pending_v2.remove(id) {
            trace!("notifying pending readers for {}", id);
            pending
                .sender
                .send(contents.payload.clone())
                .expect("sending on oneshot channel must succeed");

            contents.mark_read();
            self.read_order.push_back(*id);
        }

        trace!("storing payload for {}", id);
        let _overwritten = self.populated.insert(*id, contents);

        self.insert_order.push_back(*id);

        self.check_invariants();

        Ok(())
    }

    fn post_v1_req_and_wait(
        &mut self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<oneshot::Receiver<Vec<u8>>, Error> {
        // TODO reject duplicate v1 requests
        // self.can_wait_for_mailbox(id)?;

        // v1 requests are handled like v2 payloads, since a v2 receiver will be
        // polling for them like they would a v2 message.
        self.post_v2(id, payload).expect("must succeed writing v1 req as v2 payload");

        let (sender, receiver) = oneshot::channel::<Vec<u8>>();
        _ = self.pending_v1.insert(*id, sender);
        Ok(receiver)
    }

    fn post_v1_res(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<(), Error> {
        // TODO error if no entry, map to unavailable response

        // Discard the sender's request, since the receiver is responding they
        // definitely got it
        _ = self.populated.remove(id);

        match self.pending_v1.remove(id) {
            None => Err(Error::V1SenderUnavailable),
            Some(sender) => {
                sender.send(payload).expect("oneshot sender must succeed");
                Ok(())
            }
        }
    }

    fn len(&self) -> usize { self.populated.len() + self.pending_v1.len() + self.pending_v2.len() }

    /// Clean out the mailboxes.
    ///
    /// Since we use an RwLock and not a concurrent hashmap, there's currently
    /// no benefit to putting this in a background task.
    ///
    /// Furthermore, to improve privacy and resist mailbox enumeration, we prune
    /// expired entries eagerly.
    fn prune(&mut self) {
        let now = Instant::now();

        debug_assert!(READ_TTL < UNREAD_TTL_AT_CAPACITY); // should be a static assert
        debug_assert!(UNREAD_TTL_AT_CAPACITY < UNREAD_TTL_BELOW_CAPACITY); // should be a static assert

        // Prune any fully expired mailboxes, whether read or unread
        tracing::trace!("Pruning stale mailboxes");
        while let Some(id) = self.insert_order.pop_front() {
            if let Some(entry) = self.populated.get(&id) {
                if entry.metadata.created + UNREAD_TTL_BELOW_CAPACITY < now {
                    self.populated.remove(&id);
                    tracing::trace!("Pruned stale mailbox {id}");
                } else {
                    self.insert_order.push_front(id);
                    break;
                }
            }
        }

        // So long as there expired read mailboxes, prune those. Stop when a
        // mailbox within the TTL is encountered.
        tracing::trace!("Pruning read mailboxes");
        while let Some(id) = self.read_order.pop_front() {
            if let Some(entry) = self.populated.get(&id) {
                if let Some(instant) = entry.metadata.read {
                    if instant + READ_TTL < now {
                        self.populated.remove(&id);
                        tracing::trace!("Pruned read mailbox {id}");
                        return; // no need to prune any more
                    } else {
                        self.read_order.push_front(id);
                        break;
                    }
                }
            }
        }

        // Only then prune unread mailboxes, if space is needed using lower TTL,
        // and if capacity is not required at higher limit to reduce expire old
        // entries
        tracing::trace!("Attempting to create capacity");
        while let Some(id) = self.insert_order.pop_front() {
            if let Some(entry) = self.populated.get(&id) {
                if entry.metadata.created + UNREAD_TTL_AT_CAPACITY < now {
                    self.populated.remove(&id);
                    tracing::trace!("Pruned unread mailbox {id} to create capacity");
                    return; // no need to prune any more
                } else {
                    self.insert_order.push_front(id);
                    break;
                }
            }
        }

        tracing::trace!("Unable to prune any further, {} entries remain", self.len());
    }

    #[inline]
    fn check_invariants(&self) {
        debug_assert!(self.len() <= self.capacity);
        debug_assert!(self.insert_order.len() <= self.capacity);
        // debug_assert!(self.read_order.len() <= self.capacity); // A B A

        debug_assert!(self.read_order.len() + self.insert_order.len() <= self.capacity);
        debug_assert!(self.populated.len() <= self.insert_order.len());

        // // Why? // debug_assert!(self.read_order.len() <= self.insert_order.len());
        // debug_assert!(
        //     {
        //         let mut seen = std::collections::HashSet::new();
        //         self.read_order.iter().all(|id| seen.insert(id))
        //     },
        //     "self.read_order should not contain duplicates"
        // );

        // debug_assert!(
        //     {
        //         let mut seen = std::collections::HashSet::new();
        //         self.insert_order.iter().all(|id| seen.insert(id))
        //     },
        //     "self.insert_order should not contain duplicates"
        // );
    }
}

#[derive(Debug)]
pub enum Error {
    /// Operation rejected due to lack of capacity
    OverCapacity,

    /// Indicates the sender that was waiting for the reply is no longer there
    V1SenderUnavailable,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverCapacity => "Database over capacity".fmt(f),
            Self::V1SenderUnavailable => "Sender no longer connected".fmt(f),
        }
    }
}

impl crate::db::SendableError for Error {}

impl crate::db::Db for Db {
    type OperationalError = Error;
    async fn post_v2_payload(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<(), crate::db::Error<Self::OperationalError>> {
        let mut guard = self.0.write().await;
        guard.post_v2(id, payload).map_err(crate::db::Error::Operational)
    }

    async fn wait_for_v2_payload(
        &self,
        id: &ShortId,
    ) -> Result<Vec<u8>, crate::db::Error<Self::OperationalError>> {
        let (timeout, receiver) = {
            let mut guard = self.0.write().await;

            if let Some(payload) = guard.get(id) {
                return Ok((*payload).clone()); // TODO don't clone
            } else {
                (guard.timeout, guard.wait_v2(id).map_err(crate::db::Error::Operational)?)
            }
        };

        match tokio::time::timeout(timeout, receiver).await {
            Ok(payload) => Ok((*payload.expect("receiver must not fail")).clone()), // TODO don't clone
            Err(elapsed) => Err(crate::db::Error::Timeout(elapsed)),
        }
    }

    // TODO peek as part of this
    async fn post_v1_request_and_wait_for_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, crate::db::Error<Self::OperationalError>> {
        let (timeout, receiver) = {
            let mut guard = self.0.write().await;

            (
                guard.timeout,
                guard.post_v1_req_and_wait(id, payload).map_err(crate::db::Error::Operational)?,
            )
        };

        trace!("v1 sender waiting for v2 receiver's response");

        match tokio::time::timeout(timeout, receiver).await {
            Ok(payload) => Ok(payload.expect("receiver must not fail")),
            Err(elapsed) => Err(crate::db::Error::Timeout(elapsed)),
        }
    }

    async fn post_v1_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<(), crate::db::Error<Self::OperationalError>> {
        let mut guard = self.0.write().await;
        guard.post_v1_res(id, payload).map_err(crate::db::Error::Operational)
    }
}
