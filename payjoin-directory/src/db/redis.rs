use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use payjoin::directory::ShortId;
use redis::{AsyncCommands, Client, ErrorKind, RedisError, RedisResult};
use tracing::{debug, trace};

const DEFAULT_COLUMN: &str = "";
const PJ_V1_COLUMN: &str = "pjv1";

#[derive(Debug, Clone)]
pub struct Db {
    client: Client,
    timeout: Duration,
}

impl crate::db::SendableError for RedisError {}

pub type Result<T> = core::result::Result<T, super::Error<RedisError>>;

impl Db {
    pub async fn new(timeout: Duration, db_host: String) -> Result<Self> {
        let client = Client::open(format!("redis://{db_host}"))?;
        Ok(Self { client, timeout })
    }

    async fn peek_with_timeout(&self, mailbox_id: &ShortId, channel_type: &str) -> Result<Vec<u8>> {
        trace!("blocking on {}", mailbox_id);
        match tokio::time::timeout(self.timeout, self.peek(mailbox_id, channel_type)).await {
            Ok(redis_result) => redis_result.map_err(super::Error::Operational),
            Err(elapsed) => Err(super::Error::Timeout(elapsed)),
        }
    }

    async fn peek(&self, mailbox_id: &ShortId, channel_type: &str) -> RedisResult<Vec<u8>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = channel_name(mailbox_id, channel_type);

        // Attempt to fetch existing content for the given mailbox_id and channel_type
        if let Ok(data) = conn.get::<_, Vec<u8>>(&key).await {
            if !data.is_empty() {
                return Ok(data);
            }
        }
        debug!("Failed to fetch content initially");

        // Set up a temporary listener for changes
        let mut pubsub_conn = self.client.get_async_pubsub().await?;
        let channel_name = channel_name(mailbox_id, channel_type);
        pubsub_conn.subscribe(&channel_name).await?;

        // Use a block to limit the scope of the mutable borrow
        let data = {
            let mut message_stream = pubsub_conn.on_message();

            loop {
                match message_stream.next().await {
                    Some(msg) => {
                        trace!("got pubsub: {:?}", msg);

                        () = msg.get_payload()?; // Notification received
                                                 // Try fetching the data again
                        if let Some(data) = conn.get::<_, Option<Vec<u8>>>(&key).await? {
                            if !data.is_empty() {
                                break data; // Exit the block, returning the data
                            }
                        }
                    }
                    None =>
                        return Err(RedisError::from((
                            ErrorKind::IoError,
                            "PubSub connection closed",
                        ))),
                }
            }
        };

        // Since the stream is dropped here, we can now unsubscribe
        pubsub_conn.unsubscribe(&channel_name).await?;

        Ok(data)
    }

    async fn push(&self, mailbox_id: &ShortId, channel_type: &str, data: Vec<u8>) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = channel_name(mailbox_id, channel_type);
        () = conn.set(&key, data).await?;
        () = conn.publish(&key, "updated").await?;
        Ok(())
    }
}

impl super::Db for Db {
    type OperationalError = RedisError;

    async fn post_v2_payload(&self, mailbox_id: &ShortId, data: Vec<u8>) -> Result<Option<()>> {
        self.push(mailbox_id, DEFAULT_COLUMN, data).await.map(Some)
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> Result<Arc<Vec<u8>>> {
        self.push(mailbox_id, DEFAULT_COLUMN, data).await?;
        self.peek_with_timeout(mailbox_id, PJ_V1_COLUMN).await.map(Arc::new)
    }

    async fn wait_for_v2_payload(&self, mailbox_id: &ShortId) -> Result<Arc<Vec<u8>>> {
        self.peek_with_timeout(mailbox_id, DEFAULT_COLUMN).await.map(Arc::new)
    }

    async fn post_v1_response(&self, mailbox_id: &ShortId, data: Vec<u8>) -> Result<()> {
        self.push(mailbox_id, PJ_V1_COLUMN, data).await
    }
}

fn channel_name(mailbox_id: &ShortId, channel_type: &str) -> Vec<u8> {
    (mailbox_id.to_string() + channel_type).into_bytes()
}
