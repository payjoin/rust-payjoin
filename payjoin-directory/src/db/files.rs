use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::future::{self, FutureExt};
use payjoin::directory::ShortId;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex};
use tracing::trace;

use super::Db as DbTrait;

/// The maximum number of pending or populated mailbox entries.
///
/// Defaults to around 2e6, for a generous upper bound rounded up from ~2
/// mailboxes/tx, ~4K txs/block, and ~144 blocks/24h.
const DEFAULT_CAPACITY: usize = 1 << (1 + 12 + 8);

const DEFAULT_UNREAD_TTL_AT_CAPACITY: Duration = Duration::from_secs(60 * 60 * 24); // 1 day
const DEFAULT_UNREAD_TTL_BELOW_CAPACITY: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 1 week

/// How long read messages should be kept in mailboxes. Defaults to a 10 minute
/// grace period from first read attempt, in case of intermittent network or
/// relay errors.
const DEFAULT_READ_TTL: Duration = Duration::from_secs(60 * 10); // 10 minutes

#[derive(Debug)]
struct V2WaitMapEntry {
    receiver: future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>,
    sender: oneshot::Sender<Arc<Vec<u8>>>, // TODO [u8; 7168]
}

#[derive(Debug)]
struct V1WaitMapEntry {
    payload: Arc<Vec<u8>>,
    sender: oneshot::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Mailboxes {
    capacity: usize,
    persistent_storage: DiskStorage,
    pending_v1: HashMap<ShortId, V1WaitMapEntry>,
    pending_v2: HashMap<ShortId, V2WaitMapEntry>,
    insert_order: VecDeque<(SystemTime, ShortId)>,
    read_order: VecDeque<(SystemTime, ShortId)>,
    read_mailbox_ids: HashSet<ShortId>,
    unread_ttl_below_capacity: Duration,
    unread_ttl_at_capacity: Duration,
    read_ttl: Duration,
    early_removal_count: usize,
}

#[derive(Debug)]
struct DiskStorage {
    dir: PathBuf,
    xor: Vec<u8>,
}

impl DiskStorage {
    async fn init(dir: PathBuf) -> io::Result<Self> {
        let tmp_dir = &dir.join("tmp");
        if fs::try_exists(tmp_dir).await? {
            // clear out any tempfiles from uncompleted writes
            fs::remove_dir_all(tmp_dir).await?;
        }
        fs::create_dir_all(tmp_dir).await?;

        // XOR data with a random pattern to obfuscate v1 requests
        // and writing malicious data such as virus fingerprints
        let xor: Vec<u8>;
        let xor_file = dir.join("xor.dat");
        if fs::try_exists(&xor_file).await? {
            xor = fs::read(xor_file).await?;
        } else {
            xor = OsRng.next_u64().to_ne_bytes().to_vec();
            let mut file = fs::File::create_new(xor_file).await?;
            file.write_all(&xor).await?;
            file.sync_all().await?;
        }

        Ok(Self { dir, xor })
    }

    fn mailbox_path(&self, id: &ShortId) -> PathBuf { self.dir.join(id.to_string()) }

    fn insert_mailbox_path(&self, id: &ShortId) -> PathBuf {
        self.dir.join("tmp").join(id.to_string())
    }

    async fn contains_key(&self, id: &ShortId) -> io::Result<bool> {
        fs::try_exists(self.mailbox_path(id)).await
    }

    async fn get(&self, id: &ShortId) -> io::Result<Option<(SystemTime, Vec<u8>)>> {
        // If the file doesn't exist, it's Ok(None), not Err
        let mut file = match File::open(self.mailbox_path(id)).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };

        let created = file.metadata().await?.created()?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        self.xor_buffer(&mut buffer);

        Ok(Some((created, buffer)))
    }

    async fn try_insert(
        &self,
        id: &ShortId,
        contents: impl AsRef<[u8]>,
    ) -> io::Result<Option<SystemTime>> {
        let mailbox_path = self.mailbox_path(id);

        // Before attempting to write the file, check if it exists and fail
        // early. Otherwise the file will be written and only then linked into
        // the directory, so it will still be atomic but rejected data will be
        // written to disk and then discarded.
        if self.contains_key(id).await? {
            // Allow idempotent insertion if the contents are identical, in case
            // of OHTTP retries for the same e2e message.
            if let Ok(Some((created, existing_contents))) = self.get(id).await {
                if &existing_contents[..] == contents.as_ref() {
                    return Ok(Some(created));
                }
            }

            return Ok(None);
        }

        // Obfuscate the contents to avoid triggering antiviruses etc due to
        // malicious content.
        let mut buffer = contents.as_ref().to_vec();
        self.xor_buffer(&mut buffer);

        // Write the full contents to disk under a temp path
        let tmp_path = self.insert_mailbox_path(id);
        let mut file = fs::File::create_new(&tmp_path).await?;
        file.write_all(&buffer).await?;
        file.sync_data().await?;

        // Link the directory entry to the newly written file and unlink the
        // temporary entry (equivalent to rename() but without overwriting)
        let link_ret = fs::hard_link(&tmp_path, &mailbox_path).await;
        fs::remove_file(tmp_path).await?; // always unlink before returning

        // Return the creation time upon successful write
        match link_ret {
            Ok(()) => Ok(Some(file.metadata().await?.created()?)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn xor_buffer(&self, buffer: &mut [u8]) {
        for (byte, &pattern) in buffer.iter_mut().zip(self.xor.iter().cycle()) {
            *byte ^= pattern;
        }
    }

    async fn remove(&self, id: &ShortId) -> io::Result<Option<()>> {
        match fs::remove_file(self.mailbox_path(id)).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Ok(()) => Ok(Some(())),
            Err(e) => Err(e),
        }
    }

    /// Returns the ShortId keys sorted by their creation time
    async fn insert_order(&self) -> io::Result<Vec<(SystemTime, ShortId)>> {
        // there's no need to stream this as it only happens once on startup
        // buffering to a vec simplifies any error handling
        let mut ids: Vec<(SystemTime, ShortId)> = Vec::default();

        let mut dir_entries = fs::read_dir(&self.dir).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            if let Some(file_name) = entry.file_name().to_str() {
                if let Ok(id) = ShortId::from_str(file_name) {
                    let ctime = entry.metadata().await?.created()?;
                    ids.push((ctime, id));
                }
            }
        }

        ids.sort_by_key(|&(ctime, _id)| ctime);

        Ok(ids)
    }
}

impl Mailboxes {
    async fn init(dir: PathBuf) -> io::Result<Self> {
        let storage = DiskStorage::init(dir).await?;
        let insert_order = storage.insert_order().await?.into();
        Ok(Self {
            persistent_storage: storage,
            insert_order,
            capacity: DEFAULT_CAPACITY,
            pending_v1: HashMap::default(),
            pending_v2: HashMap::default(),
            read_order: VecDeque::default(),
            read_mailbox_ids: HashSet::default(),
            unread_ttl_below_capacity: DEFAULT_UNREAD_TTL_BELOW_CAPACITY,
            unread_ttl_at_capacity: DEFAULT_UNREAD_TTL_AT_CAPACITY,
            read_ttl: DEFAULT_READ_TTL,
            early_removal_count: 0,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Db {
    timeout: Duration,
    mailboxes: Arc<Mutex<Mailboxes>>,
}

impl Db {
    pub async fn init(timeout: Duration, path: PathBuf) -> io::Result<Self> {
        Ok(Self { timeout, mailboxes: Arc::new(Mutex::new(Mailboxes::init(path).await?)) })
    }

    pub async fn prune(&self) -> io::Result<Duration> { self.mailboxes.lock().await.prune().await }

    pub async fn spawn_background_prune(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                // TODO allow cancellation?
                let sleep_for =
                    { this.mailboxes.lock().await.prune().await.expect("disk storage failed") };
                tokio::time::sleep(sleep_for).await;
            }
        });
    }
}

impl DbTrait for Db {
    type OperationalError = io::Error;
    async fn post_v2_payload(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Option<()>, super::Error<Self::OperationalError>> {
        let mut guard = self.mailboxes.lock().await;
        Ok(guard.post_v2(id, payload).await?)
    }

    async fn wait_for_v2_payload(
        &self,
        id: &ShortId,
    ) -> Result<Arc<Vec<u8>>, super::Error<Self::OperationalError>> {
        let receiver = {
            let mut guard = self.mailboxes.lock().await;

            if let Some(payload) = guard.read(id).await? {
                return Ok(payload);
            } else {
                guard.wait_v2(id).await?
            }
        };

        let ret = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(payload) => Ok((payload.expect("receiver must not fail")).clone()),
            Err(elapsed) => Err(super::Error::Timeout(elapsed)),
        };

        self.mailboxes.lock().await.maybe_cleanup_v2_waitmap(id);

        ret
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Arc<Vec<u8>>, super::Error<Self::OperationalError>> {
        let receiver = {
            self.mailboxes
                .lock()
                .await
                .post_v1_req_and_wait(id, payload)
                .await?
                .ok_or(super::Error::OverCapacity)?
        };

        trace!("v1 sender waiting for v2 receiver's response");

        let ret = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(payload) => Ok(Arc::new(payload.expect("receiver must not fail"))),
            Err(elapsed) => Err(super::Error::Timeout(elapsed)),
        };

        // unconditionally clear the pending v1 entry. on timeout, the sender
        // will no longer be available to process any replies so there is no
        // point delivering the request to the receiver
        self.mailboxes.lock().await.pending_v1.remove(id);

        ret
    }

    async fn post_v1_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<(), super::Error<Self::OperationalError>> {
        let mut guard = self.mailboxes.lock().await;
        Ok(guard.post_v1_res(id, payload).await?)
    }
}

// The async methods here generally use &mut self, and therefore assume mutex
// ownership of the mailbox struct. this means they are supposed to return
// quickly. however, they will wait for sync() on write, as the implies minimum
// number of requests per second is only 25, holding the mutex while waiting for
// disk and thereby serializing all writes should be fine even without an SSD.
impl Mailboxes {
    async fn read(&mut self, id: &ShortId) -> io::Result<Option<Arc<Vec<u8>>>> {
        // V1 POST requests are only stored in memory since they are
        // unencrypted. Check this hash table first.
        if let Some(V1WaitMapEntry { payload, .. }) = self.pending_v1.get(id) {
            return Ok(Some(payload.clone()));
        }

        // V2 requests are stored on disk
        if let Some((_created, payload)) = self.persistent_storage.get(id).await? {
            self.mark_read(id);
            return Ok(Some(Arc::new(payload)));
        }

        Ok(None)
    }

    fn mark_read(&mut self, id: &ShortId) {
        if self.read_mailbox_ids.insert(*id) {
            self.read_order.push_back((SystemTime::now(), *id));
        }
    }

    async fn has_capacity(&mut self) -> io::Result<bool> {
        self.maybe_prune().await?;
        Ok(self.len() < self.capacity)
    }

    async fn wait_v2(
        &mut self,
        id: &ShortId,
    ) -> Result<future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>, Error> {
        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        if self.pending_v1.contains_key(id) {
            return Err(Error::OverCapacity);
        }

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

        Ok(receiver)
    }

    fn maybe_cleanup_v2_waitmap(&mut self, id: &ShortId) {
        if let Some(entry) = self.pending_v2.get(id) {
            if entry.receiver.strong_count().unwrap_or(0) <= 1 {
                self.pending_v2.remove(id);
            }
        }
    }

    async fn post_v2(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<Option<()>, Error> {
        let Some(created) = self.persistent_storage.try_insert(id, &payload).await? else {
            return Ok(None);
        };

        self.insert_order.push_back((created, *id));

        // If there are pending readers, satisfy them and mark the payload as read
        if let Some(pending) = self.pending_v2.remove(id) {
            trace!("notifying pending readers for {}", id);

            self.mark_read(id);

            pending
                .sender
                .send(Arc::new(payload))
                .expect("sending on oneshot channel must succeed");
        }

        Ok(Some(()))
    }

    async fn post_v1_req_and_wait(
        &mut self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Option<oneshot::Receiver<Vec<u8>>>, Error> {
        let mut ret = None;
        let payload = Arc::new(payload);

        // Don't overwrite in flight requests
        self.pending_v1.entry(*id).or_insert_with(|| {
            let payload = payload.clone();
            let (sender, receiver) = oneshot::channel::<Vec<u8>>();
            ret = Some(receiver);
            V1WaitMapEntry { payload, sender }
        });

        // If there are pending readers, satisfy them and mark the payload as read
        if let Some(pending) = self.pending_v2.remove(id) {
            trace!("notifying pending readers for {} (v1 fallback)", id);
            pending.sender.send(payload).expect("sending on oneshot channel must succeed");
        }

        Ok(ret)
    }

    async fn remove(&mut self, id: &ShortId) -> io::Result<Option<()>> {
        self.read_mailbox_ids.remove(id);
        self.persistent_storage.remove(id).await
    }

    async fn post_v1_res(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<(), Error> {
        match self.pending_v1.remove(id) {
            None => Err(Error::V1SenderUnavailable),
            Some(V1WaitMapEntry { sender, .. }) =>
                sender.send(payload).map_err(|_| Error::V1SenderUnavailable),
        }
    }

    fn len(&self) -> usize {
        (self.insert_order.len() - self.early_removal_count)
            + self.pending_v1.len()
            + self.pending_v2.len()
    }

    async fn maybe_prune(&mut self) -> io::Result<Duration> {
        // TODO make this lazier, once per time interval, or once per n checks
        // or both
        self.prune().await
    }

    /// Clean out the mailboxes.
    ///
    /// Since we use a mutex and not a concurrent hashmap, there's currently
    /// no benefit to putting this in a background task.
    ///
    /// Furthermore, to improve privacy and resist mailbox enumeration, we prune
    /// expired entries eagerly.
    async fn prune(&mut self) -> io::Result<Duration> {
        trace!("pruning");
        let now = SystemTime::now();

        debug_assert!(self.read_ttl < self.unread_ttl_at_capacity);
        debug_assert!(self.unread_ttl_at_capacity < self.unread_ttl_below_capacity);
        debug_assert!(self.pending_v1.iter().all(|(_, v)| !v.sender.is_closed()));

        // Prune in flight requests, these can persist in the case of an incomplete session
        self.pending_v2.retain(|_, v| v.receiver.strong_count().unwrap_or(0) > 1);

        // Prune any fully expired mailboxes, whether read or unread
        while let Some((created, id)) = self.insert_order.front().cloned() {
            println!(
                "checking if {id} elapsed: {:?} < {:?} = {}",
                (created + self.unread_ttl_below_capacity),
                now,
                (created + self.unread_ttl_below_capacity) < now,
            );
            if created + self.unread_ttl_below_capacity < now {
                debug_assert!(self.insert_order.len() >= self.early_removal_count);
                _ = self.insert_order.pop_front();
                if self.remove(&id).await?.is_none() {
                    self.early_removal_count = self
                        .early_removal_count
                        .checked_sub(1)
                        .expect("early removal adjustment should never underflow");
                }
                debug_assert!(self.insert_order.len() >= self.early_removal_count);
                trace!("Pruned old mailbox {id}");
            } else {
                break;
            }
        }

        // So long as there expired read mailboxes, prune those. Stop when a
        // mailbox within the TTL is encountered.
        while let Some((read, id)) = self.read_order.front().cloned() {
            println!(
                "checking if {id} elapsed (read ttl): {:?} < {:?} = {}",
                (read + self.read_ttl),
                now,
                (read + self.read_ttl) < now,
            );
            if read + self.read_ttl < now {
                println!("removing");
                _ = self.read_order.pop_front();
                if self.remove(&id).await?.is_some() {
                    self.early_removal_count += 1;
                    debug_assert!(self.insert_order.len() >= self.early_removal_count);
                }
                trace!("Pruned read mailbox {id}");
            } else {
                break;
            }
        }

        // If no room was created, try to prune the oldest unread mailbox if
        // it's over the minimum TTL
        debug_assert!(self.len() <= self.capacity);
        if self.len() == self.capacity {
            if let Some((created, id)) = self.insert_order.front().cloned() {
                if created + self.unread_ttl_at_capacity < now {
                    _ = self.insert_order.pop_front();
                    self.remove(&id).await?;
                    trace!("Pruned unread mailbox {id} to make room");
                } else {
                    trace!("Nothing to prune, {} entries remain", self.len());
                }
            }
        }

        Ok(self.next_prune())
    }

    fn next_prune(&mut self) -> Duration {
        let earliest_read_prune_opportunity = self
            .read_order
            .front()
            .map(|(read, _id)| {
                self.read_ttl
                    .checked_sub(read.elapsed().expect("system clock moved back"))
                    .unwrap_or(self.read_ttl)
            })
            .unwrap_or_else(|| self.read_ttl);

        let earliest_unread_prune_opportunity = self
            .insert_order
            .front()
            .map(|(created, _id)| {
                self.unread_ttl_at_capacity
                    .checked_sub(created.elapsed().expect("system clock moved back"))
                    .unwrap_or(self.unread_ttl_at_capacity)
            })
            .unwrap_or_else(|| self.unread_ttl_at_capacity);

        std::cmp::min(earliest_read_prune_opportunity, earliest_unread_prune_opportunity)
    }
}

#[derive(Debug)]
pub enum Error {
    /// Operation rejected due to lack of capacity
    OverCapacity,

    /// Indicates the sender that was waiting for the reply is no longer there
    V1SenderUnavailable,

    IO(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Self::IO(e) }
}

// FIXME why isn't this sufficient for ?, necessitating ugly map_err(into)?
impl From<Error> for super::Error<std::io::Error> {
    fn from(val: Error) -> super::Error<io::Error> {
        match val {
            Error::V1SenderUnavailable => super::Error::V1SenderUnavailable,
            Error::OverCapacity => super::Error::OverCapacity,
            Error::IO(e) => super::Error::Operational(e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            OverCapacity => "Database over capacity".fmt(f),
            V1SenderUnavailable => "Sender no longer connected".fmt(f),
            IO(e) => write!(f, "Internal Error: {e}"),
        }
    }
}

impl super::SendableError for Error {}

#[tokio::test]
async fn test_disk_storage_initialization() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    assert!(!dir.path().join("tmp").exists(), "tmp subdirectory should not have been created yet");

    let xor_pattern = {
        let storage = DiskStorage::init(dir.path().to_owned())
            .await
            .expect("initializing storage directory should succeed");

        assert!(dir.path().join("tmp").exists(), "tmp subdirectory should have been created");
        assert!(
            dir.path().join("xor.dat").exists(),
            "random obfuscation pattern should have been generated"
        );

        fs::write(dir.path().join("tmp").join("blah"), "junk").await?;

        storage.xor
    };

    assert!(
        dir.path().join("tmp").join("blah").exists(),
        "temp file should not have been cleared yet"
    );
    let storage = DiskStorage::init(dir.path().to_owned())
        .await
        .expect("initializing storage directory should succeed");

    assert!(!dir.path().join("tmp").join("blah").exists(), "temp file should have been cleared");

    assert_eq!(storage.xor, xor_pattern, "xor pattern loaded from file");

    Ok(())
}

#[tokio::test]
async fn test_disk_storage_mailboxes() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;

    let storage = DiskStorage::init(dir.path().to_owned())
        .await
        .expect("initializing storage directory should succeed");

    let id1 = ShortId::try_from(&(b"12345678")[..]).unwrap();
    let id2 = ShortId::try_from(&(b"87654321")[..]).unwrap();

    assert!(!storage
        .contains_key(&id1)
        .await
        .expect("checking mailbox existence should not error"));
    assert!(!storage
        .contains_key(&id2)
        .await
        .expect("checking mailbox existence should not error"));
    assert!(matches!(storage.get(&id1).await, Ok(None)));
    assert!(matches!(storage.get(&id2).await, Ok(None)));

    let contents1 = b"OH HAI";
    let contents2 = b"HI FREN";

    let created1 = storage
        .try_insert(&id1, contents1)
        .await
        .expect("writing should succeed")
        .expect("writing should return a creation time");

    match storage.get(&id1).await {
        Ok(Some((got_created, got_contents))) => {
            assert_eq!(got_created, created1.to_owned());
            assert_eq!(got_contents, contents1.to_owned());
        }
        e => {
            e.expect("retrieval should work");
        }
    };

    assert!(matches!(storage.get(&id2).await, Ok(None)));

    assert!(
        storage
            .try_insert(&id1, contents2)
            .await
            .expect("writing a second time should not fail with IO error")
            .is_none(),
        "writing a second time should be rejected",
    );

    assert_eq!(
        storage.try_insert(&id1, contents1).await.expect("idempotent write should not fail"),
        Some(created1),
        "idempotent write should have the same creation time",
    );

    tokio::time::sleep(Duration::from_millis(1)).await;

    let created2 = storage
        .try_insert(&id2, contents2)
        .await
        .expect("writing should succeed")
        .expect("writing should return a creation time");

    assert!(created1 < created2, "creation times should be ordered as expected");

    assert_eq!(
        storage.insert_order().await.expect("enumeration should succeed"),
        vec![(created1, id1), (created2, id2)],
        "enumeration should return expected keys and creation times",
    );

    let mut file_contents =
        fs::read(storage.mailbox_path(&id1)).await.expect("mailbox file should be readable");

    assert_eq!(file_contents.len(), contents1.len(), "file data should have the right length");
    assert_ne!(file_contents, contents1, "file data should be obfuscated");

    storage.xor_buffer(&mut file_contents[..]);
    assert_eq!(file_contents, contents1, "deobfuscation should recover contents");

    storage.remove(&id1).await.expect("removing an existing mailbox should succeed");
    assert!(
        !storage.contains_key(&id1).await.expect("checking existence should not error"),
        "mailbox file should no longer exist"
    );
    storage.remove(&id1).await.expect("removing a non-existing mailbox should still not error");

    assert_eq!(
        storage.insert_order().await.expect("enumeration should succeed"),
        vec![(created2, id2)],
        "enumeration should return expected keys and creation times",
    );

    Ok(())
}

#[tokio::test]
async fn test_mailbox_storage() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;

    let db = Db::init(Duration::from_millis(10), dir.path().to_owned())
        .await
        .expect("initializing mailbox database should succeed");

    let id = ShortId([0u8; 8]);
    let contents = b"foo bar";
    db.post_v2_payload(&id, contents.to_vec())
        .await
        .expect("posting payload should succeed")
        .expect("contents should be accepted");

    let res = db.wait_for_v2_payload(&id).await.expect("waiting for payload should succeed");
    assert_eq!(&res[..], contents, "posted payload should be retrievable");

    Ok(())
}

#[tokio::test]
async fn test_v2_wait() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;

    let db = Db::init(Duration::from_millis(1), dir.path().to_owned())
        .await
        .expect("initializing mailbox database should succeed");

    let id = ShortId([0u8; 8]);
    let contents = b"foo bar";

    match db.wait_for_v2_payload(&id).await {
        Err(super::Error::Timeout(_)) => {}
        res => panic!("expected timeout, got {:?}", res),
    }

    let read_task1 = tokio::spawn({
        let db = db.clone();
        async move { db.wait_for_v2_payload(&id).await }
    });
    let read_task2 = tokio::spawn({
        let db = db.clone();
        async move { db.wait_for_v2_payload(&id).await }
    });

    db.post_v2_payload(&id, contents.to_vec())
        .await
        .expect("posting payload should succeed")
        .expect("contents should be accepted");

    let res = read_task1
        .await
        .expect("joining task should succeed")
        .expect("waiting for payload should succeed");
    assert_eq!(&res[..], contents, "posted payload should be retrievable");

    let res = read_task2
        .await
        .expect("joining task should succeed")
        .expect("waiting for payload should succeed");
    assert_eq!(&res[..], contents, "posted payload should be retrievable");

    assert!(
        db.post_v2_payload(&id, b"something else".to_vec())
            .await
            .expect("posting payload should succeed")
            .is_none(),
        "duplicate POST should be rejected"
    );

    let res = db.wait_for_v2_payload(&id).await.expect("reading payload should succeed");
    assert_eq!(&res[..], contents, "posted payload should be retrievable");

    Ok(())
}

#[tokio::test]
async fn test_v1_wait() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;

    let db = Arc::new(
        Db::init(Duration::from_millis(1), dir.path().to_owned())
            .await
            .expect("initializing mailbox database should succeed"),
    );

    let id = ShortId([0u8; 8]);

    let v1_sender_task = tokio::spawn({
        let db = db.clone();
        async move { db.post_v1_request_and_wait_for_response(&id, b"request".to_vec()).await }
    });

    let res = db.wait_for_v2_payload(&id).await.expect("reading payload should succeed");
    assert_eq!(&res[..], b"request", "in flight v1 request should be retrievable");

    assert!(
        matches!(
            db.post_v1_request_and_wait_for_response(&id, b"different request".to_vec()).await,
            Err(super::Error::OverCapacity),
        ),
        "second v1 sender with the same shortid should be rejected while request is in flight",
    );

    db.post_v1_response(&id, b"response".to_vec()).await.expect("posting payload should succeed");

    let res = v1_sender_task
        .await
        .expect("joining task should succeed")
        .expect("waiting for payload should succeed");
    assert_eq!(&res[..], b"response", "should be response from v2 receiver");

    assert!(
        matches!(
            db.post_v1_response(&id, b"response".to_vec()).await,
            Err(super::Error::V1SenderUnavailable)
        ),
        "posting without a v1 sender waiting should fail"
    );

    Ok(())
}

// Simulate elapsed time deterministically by shifting stored timestamps
// backward instead of sleeping. tokio::time::pause() can't be used because
// prune compares against SystemTime (timestamps originate from disk).
#[tokio::test]
async fn test_prune() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;

    let db = Db::init(Duration::from_millis(2), dir.path().to_owned())
        .await
        .expect("initializing mailbox database should succeed");

    let read_ttl = Duration::from_secs(60);
    let unread_ttl_at_capacity = Duration::from_secs(600);
    let unread_ttl_below_capacity = Duration::from_secs(3600);

    {
        let mut guard = db.mailboxes.lock().await;
        guard.capacity = 2;
        guard.read_ttl = read_ttl;
        guard.unread_ttl_at_capacity = unread_ttl_at_capacity;
        guard.unread_ttl_below_capacity = unread_ttl_below_capacity;
    }

    assert_eq!(db.mailboxes.lock().await.len(), 0);
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 0);

    let id = ShortId([0u8; 8]);
    let contents = b"fooo";

    // Pending v2 waiter that times out should be cleaned up by prune
    let read_task1 = tokio::spawn({
        let db = db.clone();
        async move { db.wait_for_v2_payload(&id).await }
    });

    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(db.mailboxes.lock().await.len(), 1);

    match read_task1.await.expect("joining should succeed") {
        Err(super::Error::Timeout(_)) => {}
        res => panic!("expected timeout, got {res:?}"),
    }

    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 0);

    // Post a v2 payload — should survive immediate prune (TTL not elapsed)
    db.post_v2_payload(&id, contents.to_vec())
        .await
        .expect("posting payload should succeed")
        .expect("contents should be accepted");

    assert_eq!(db.mailboxes.lock().await.len(), 1);
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 1);

    // Shift insert timestamps past unread_ttl_below_capacity
    {
        let mut guard = db.mailboxes.lock().await;
        for (ts, _) in guard.insert_order.iter_mut() {
            *ts = *ts - (unread_ttl_below_capacity + Duration::from_secs(1));
        }
    }

    assert_eq!(db.mailboxes.lock().await.len(), 1);
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 0);

    // Post again, read it, then verify read TTL pruning
    db.post_v2_payload(&id, contents.to_vec())
        .await
        .expect("posting payload should succeed")
        .expect("contents should be accepted");

    assert_eq!(db.mailboxes.lock().await.len(), 1);

    // Mark the mailbox as read
    _ = db.wait_for_v2_payload(&id).await.expect("waiting for payload should succeed");

    assert_eq!(db.mailboxes.lock().await.len(), 1);
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 1);

    // Shift read timestamps past read_ttl
    {
        let mut guard = db.mailboxes.lock().await;
        for (ts, _) in guard.read_order.iter_mut() {
            *ts = *ts - (read_ttl + Duration::from_secs(1));
        }
    }

    assert_eq!(db.mailboxes.lock().await.len(), 1);
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 0);

    // Empty db should remain empty after prune
    db.prune().await.expect("pruning should not fail");
    assert_eq!(db.mailboxes.lock().await.len(), 0);

    Ok(())
}
