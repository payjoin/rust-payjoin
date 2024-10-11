use std::time::Duration;

use futures::StreamExt;
use redis::{AsyncCommands, Client, ErrorKind, RedisError, RedisResult};
use tracing::debug;

const DEFAULT_COLUMN: &str = "";
const PJ_V1_COLUMN: &str = "pjv1";

#[derive(Debug, Clone)]
pub(crate) struct DbPool {
    client: Client,
    timeout: Duration,
}

impl DbPool {
    pub async fn new(timeout: Duration, db_host: String) -> RedisResult<Self> {
        let client = Client::open(format!("redis://{}", db_host))?;
        Ok(Self { client, timeout })
    }

    pub async fn push_default(&self, pubkey_id: &str, data: Vec<u8>) -> RedisResult<()> {
        self.push(pubkey_id, DEFAULT_COLUMN, data).await
    }

    pub async fn peek_default(&self, pubkey_id: &str) -> Option<RedisResult<Vec<u8>>> {
        self.peek_with_timeout(pubkey_id, DEFAULT_COLUMN).await
    }

    pub async fn push_v1(&self, pubkey_id: &str, data: Vec<u8>) -> RedisResult<()> {
        self.push(pubkey_id, PJ_V1_COLUMN, data).await
    }

    pub async fn peek_v1(&self, pubkey_id: &str) -> Option<RedisResult<Vec<u8>>> {
        self.peek_with_timeout(pubkey_id, PJ_V1_COLUMN).await
    }

    async fn push(&self, pubkey_id: &str, channel_type: &str, data: Vec<u8>) -> RedisResult<()> {
        let mut conn = self.client.get_async_connection().await?;
        let key = channel_name(pubkey_id, channel_type);
        conn.set(&key, data.clone()).await?;
        conn.publish(&key, "updated").await?;
        Ok(())
    }

    async fn peek_with_timeout(
        &self,
        pubkey_id: &str,
        channel_type: &str,
    ) -> Option<RedisResult<Vec<u8>>> {
        tokio::time::timeout(self.timeout, self.peek(pubkey_id, channel_type)).await.ok()
    }

    async fn peek(&self, pubkey_id: &str, channel_type: &str) -> RedisResult<Vec<u8>> {
        let mut conn = self.client.get_async_connection().await?;
        let key = channel_name(pubkey_id, channel_type);

        // Attempt to fetch existing content for the given pubkey_id and channel_type
        if let Ok(data) = conn.get::<_, Vec<u8>>(&key).await {
            if !data.is_empty() {
                return Ok(data);
            }
        }
        debug!("Failed to fetch content initially");

        // Set up a temporary listener for changes
        let mut pubsub_conn = self.client.get_async_connection().await?.into_pubsub();
        let channel_name = channel_name(pubkey_id, channel_type);
        pubsub_conn.subscribe(&channel_name).await?;

        // Use a block to limit the scope of the mutable borrow
        let data = {
            let mut message_stream = pubsub_conn.on_message();

            loop {
                match message_stream.next().await {
                    Some(msg) => {
                        msg.get_payload()?; // Notification received
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
}

fn channel_name(pubkey_id: &str, channel_type: &str) -> String {
    format!("{}:{}", pubkey_id, channel_type)
}
