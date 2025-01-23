use std::time::Duration;

use futures::StreamExt;
use payjoin::directory::ShortId;
use redis::{AsyncCommands, Client, ErrorKind, RedisError, RedisResult};
use tracing::debug;

const DEFAULT_COLUMN: &str = "";
const PJ_V1_COLUMN: &str = "pjv1";

#[derive(Debug, Clone)]
pub(crate) struct DbPool {
    client: Client,
    timeout: Duration,
}

/// Errors pertaining to [`DbPool`]
#[derive(Debug)]
pub(crate) enum Error {
    Redis(RedisError),
    Timeout(tokio::time::error::Elapsed),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;

        match &self {
            Redis(error) => write!(f, "Redis error: {}", error),
            Timeout(timeout) => write!(f, "Timeout: {}", timeout),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Redis(e) => Some(e),
            Error::Timeout(e) => Some(e),
        }
    }
}

impl From<RedisError> for Error {
    fn from(value: RedisError) -> Self { Error::Redis(value) }
}

pub(crate) type Result<T> = core::result::Result<T, Error>;

impl DbPool {
    pub async fn new(timeout: Duration, db_host: String) -> Result<Self> {
        let client = Client::open(format!("redis://{}", db_host))?;
        Ok(Self { client, timeout })
    }

    /// Peek using [`DEFAULT_COLUMN`] as the channel type.
    pub async fn push_default(&self, subdirectory_id: &ShortId, data: Vec<u8>) -> Result<()> {
        self.push(subdirectory_id, DEFAULT_COLUMN, data).await
    }

    pub async fn peek_default(&self, subdirectory_id: &ShortId) -> Result<Vec<u8>> {
        self.peek_with_timeout(subdirectory_id, DEFAULT_COLUMN).await
    }

    pub async fn push_v1(&self, subdirectory_id: &ShortId, data: Vec<u8>) -> Result<()> {
        self.push(subdirectory_id, PJ_V1_COLUMN, data).await
    }

    /// Peek using [`PJ_V1_COLUMN`] as the channel type.
    pub async fn peek_v1(&self, subdirectory_id: &ShortId) -> Result<Vec<u8>> {
        self.peek_with_timeout(subdirectory_id, PJ_V1_COLUMN).await
    }

    async fn push(
        &self,
        subdirectory_id: &ShortId,
        channel_type: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        let key = channel_name(subdirectory_id, channel_type);
        () = conn.set(&key, data.clone()).await?;
        () = conn.publish(&key, "updated").await?;
        Ok(())
    }

    async fn peek_with_timeout(
        &self,
        subdirectory_id: &ShortId,
        channel_type: &str,
    ) -> Result<Vec<u8>> {
        match tokio::time::timeout(self.timeout, self.peek(subdirectory_id, channel_type)).await {
            Ok(redis_result) => match redis_result {
                Ok(result) => Ok(result),
                Err(redis_err) => Err(Error::Redis(redis_err)),
            },
            Err(elapsed) => Err(Error::Timeout(elapsed)),
        }
    }

    async fn peek(&self, subdirectory_id: &ShortId, channel_type: &str) -> RedisResult<Vec<u8>> {
        let mut conn = self.client.get_async_connection().await?;
        let key = channel_name(subdirectory_id, channel_type);

        // Attempt to fetch existing content for the given subdirectory_id and channel_type
        if let Ok(data) = conn.get::<_, Vec<u8>>(&key).await {
            if !data.is_empty() {
                return Ok(data);
            }
        }
        debug!("Failed to fetch content initially");

        // Set up a temporary listener for changes
        let mut pubsub_conn = self.client.get_async_connection().await?.into_pubsub();
        let channel_name = channel_name(subdirectory_id, channel_type);
        pubsub_conn.subscribe(&channel_name).await?;

        // Use a block to limit the scope of the mutable borrow
        let data = {
            let mut message_stream = pubsub_conn.on_message();

            loop {
                match message_stream.next().await {
                    Some(msg) => {
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
}

fn channel_name(subdirectory_id: &ShortId, channel_type: &str) -> Vec<u8> {
    (subdirectory_id.to_string() + channel_type).into_bytes()
}
