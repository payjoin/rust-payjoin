use std::time::Duration;

use anyhow::Result;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgPool, Pool, Postgres};
use tracing::debug;

const RES_COLUMN: &str = "res";
const REQ_COLUMN: &str = "req";

pub struct DbPool {
    pool: Pool<Postgres>,
    timeout: Duration,
}

impl DbPool {
    /// Initialize a database connection pool with specified peek timeout
    pub async fn new(timeout: Duration, db_host: String) -> Result<Self> {
        let pool = init_postgres(db_host).await?;
        Ok(Self { pool, timeout })
    }

    pub async fn peek_req(&self, pubkey_id: &str) -> Option<Result<Vec<u8>, sqlx::Error>> {
        peek_with_timeout(&self.pool, pubkey_id, REQ_COLUMN, self.timeout).await
    }
    pub async fn peek_res(&self, pubkey_id: &str) -> Option<Result<Vec<u8>, sqlx::Error>> {
        debug!("peek res");
        peek_with_timeout(&self.pool, pubkey_id, RES_COLUMN, self.timeout).await
    }

    pub async fn push_req(&self, pubkey_id: &str, data: Vec<u8>) -> Result<(), sqlx::Error> {
        push(&self.pool, pubkey_id, REQ_COLUMN, data).await
    }

    pub async fn push_res(&self, pubkey_id: &str, data: Vec<u8>) -> Result<(), sqlx::Error> {
        debug!("push res");
        push(&self.pool, pubkey_id, RES_COLUMN, data).await
    }
}

impl Clone for DbPool {
    fn clone(&self) -> Self { Self { pool: self.pool.clone(), timeout: self.timeout } }
}

async fn init_postgres(db_host: String) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .connect(&format!("postgres://postgres:welcome@{}/postgres", db_host))
        .await?;
    // Create table if not exist yet
    let (table_exists,): (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = 'directory')")
            .fetch_one(&pool)
            .await?;

    if !table_exists {
        // Create the table
        sqlx::query(
            r#"
            CREATE TABLE directory (
                pubkey_id VARCHAR PRIMARY KEY,
                req BYTEA,
                res BYTEA
            );
        "#,
        )
        .execute(&pool)
        .await?;

        // Create the function for notification
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION notify_change()
            RETURNS TRIGGER AS $$
            DECLARE
                channel_name text;
            BEGIN
                channel_name := NEW.pubkey_id || '_' || TG_ARGV[0];
                PERFORM pg_notify(channel_name, TG_TABLE_NAME || ', ' || NEW.pubkey_id);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        "#,
        )
        .execute(&pool)
        .await?;

        // Create triggers
        sqlx::query(
            r#"
            CREATE TRIGGER directory_req_trigger
            AFTER INSERT OR UPDATE OF req ON directory
            FOR EACH ROW
            EXECUTE FUNCTION notify_change('req');
        "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TRIGGER directory_res_trigger
            AFTER INSERT OR UPDATE OF res ON directory
            FOR EACH ROW
            EXECUTE FUNCTION notify_change('res');
        "#,
        )
        .execute(&pool)
        .await?;
    }
    Ok(pool)
}

async fn push(
    pool: &Pool<Postgres>,
    pubkey_id: &str,
    channel_type: &str,
    data: Vec<u8>,
) -> Result<(), sqlx::Error> {
    // Use an UPSERT operation to insert or update the record
    let query = format!(
        "INSERT INTO directory (pubkey_id, {}) VALUES ($1, $2) \
        ON CONFLICT (pubkey_id) DO UPDATE SET {} = EXCLUDED.{}",
        channel_type, channel_type, channel_type
    );

    sqlx::query(&query).bind(pubkey_id).bind(data).execute(pool).await?;

    Ok(())
}

async fn peek_with_timeout(
    pool: &Pool<Postgres>,
    pubkey_id: &str,
    channel_type: &str,
    timeout: Duration,
) -> Option<Result<Vec<u8>, sqlx::Error>> {
    tokio::time::timeout(timeout, peek(pool, pubkey_id, channel_type)).await.ok()
}

async fn peek(
    pool: &Pool<Postgres>,
    pubkey_id: &str,
    channel_type: &str,
) -> Result<Vec<u8>, sqlx::Error> {
    // Step 1: Attempt to fetch existing content for the given pubkey_id and channel_type
    match sqlx::query_as::<Postgres, (Option<Vec<u8>>,)>(&format!(
        "SELECT {} FROM directory WHERE pubkey_id = $1",
        channel_type
    ))
    .bind(pubkey_id)
    .fetch_one(pool)
    .await
    {
        Ok(row) =>
            if let Some(content) = row.0 {
                if !content.is_empty() {
                    return Ok(content);
                }
            },
        Err(e) => {
            debug!("Failed to fetch content initially: {}", e);
            // We'll continue to the next step even if the query failed
        }
    }

    // Step 2: If no content was found, set up a listener
    let mut listener = PgListener::connect_with(pool).await?;
    let channel_name = format!("{}_{}", pubkey_id, channel_type);
    listener.listen(&channel_name).await?;
    debug!("Listening on channel: {}", channel_name);

    // Step 3: Wait for a notification and then fetch the new content
    loop {
        let notification = listener.recv().await?;
        debug!("Received notification: {:?}", notification);
        if notification.channel() == channel_name {
            let row: (Vec<u8>,) = sqlx::query_as(&format!(
                "SELECT {} FROM directory WHERE pubkey_id = $1",
                channel_type
            ))
            .bind(pubkey_id)
            .fetch_one(pool)
            .await?;

            let updated_content = row.0;
            if !updated_content.is_empty() {
                return Ok(updated_content);
            }
        }
    }
}
