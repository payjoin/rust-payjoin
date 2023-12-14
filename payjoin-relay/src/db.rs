use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use redis::{Client, Commands, RedisError};

const RES_COLUMN: &str = "res";
const REQ_COLUMN: &str = "req";

#[derive(Clone)]
pub(crate) struct DbPool {
    connection: Arc<Mutex<redis::Connection>>,
}

impl DbPool {
    pub fn new(db_host: String) -> Result<Self> {
        let client = Client::open(db_host)?;
        let connection = Arc::new(Mutex::new(client.get_connection()?));
        Ok(Self { connection })
    }

    async fn publish(&self, key: String, data: Vec<u8>) -> Result<(), RedisError> {
        let mut connection = self.connection.lock().unwrap();
        let _: i32 = connection.publish(key, data)?;
        Ok(())
    }

    async fn subscribe(&self, key: String) -> Result<Vec<u8>, RedisError> {
        let mut connection = self.connection.lock().unwrap();
        let mut pubsub = connection.as_pubsub();
        pubsub.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        pubsub.subscribe(&key)?;
        let msg = pubsub.get_message()?;
        let channel = msg.get_channel_name();
        assert!(channel == key.clone());
        let payload: Vec<u8> = msg.get_payload()?;
        return Ok(payload);
    }

    pub async fn push_req(&mut self, pubkey_id: &str, data: Vec<u8>) -> Result<(), RedisError> {
        let key = format!("{}:{}", REQ_COLUMN, pubkey_id);
        self.publish(key, data).await
    }
    pub async fn push_res(&mut self, pubkey_id: &str, data: Vec<u8>) -> Result<(), RedisError> {
        let key = format!("{}:{}", RES_COLUMN, pubkey_id);
        self.publish(key, data).await
    }
    pub async fn peek_req(self, pubkey_id: &str) -> Result<Vec<u8>, RedisError> {
        let key = format!("{}:{}", REQ_COLUMN, pubkey_id);
        self.subscribe(key).await
    }
    pub async fn peek_res(self, pubkey_id: &str) -> Result<Vec<u8>, RedisError> {
        let key = format!("{}:{}", RES_COLUMN, pubkey_id);
        self.subscribe(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db() {
        let db = DbPool::new("redis://127.0.0.1/".to_string()).unwrap();
        let req = db.clone().peek_req("test").await;
        db.clone().push_req("test", vec![1, 2, 3]).await.unwrap();
        assert_eq!(req, Ok(vec![1, 2, 3]));
    }
}
