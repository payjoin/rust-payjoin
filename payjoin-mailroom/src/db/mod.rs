use std::future::Future;
use std::io;
use std::result::Result;
use std::sync::Arc;

use payjoin::directory::ShortId;
use tower::util::BoxCloneSyncService;
use tower::{Service, ServiceExt};

pub mod files;

pub trait SendableError:
    std::error::Error + std::marker::Send + std::marker::Sync + std::convert::Into<anyhow::Error>
{
}

#[derive(Debug)]
pub enum Error<OperationalError: SendableError> {
    Operational(OperationalError),
    Timeout(tokio::time::error::Elapsed),
    OverCapacity,
    AlreadyRead,
    V1SenderUnavailable,
}

impl SendableError for tokio::time::error::Elapsed {}
impl SendableError for std::io::Error {}

impl<E: SendableError> From<E> for Error<E> {
    fn from(value: E) -> Self { Error::Operational(value) }
}

impl<E: SendableError> std::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match &self {
            Operational(error) => write!(f, "Db error: {error}"),
            Timeout(timeout) => write!(f, "Timeout: {timeout}"),
            OverCapacity => "Database over capacity".fmt(f),
            AlreadyRead => "Mailbox payload already read".fmt(f),
            V1SenderUnavailable => "Sender no longer connected".fmt(f),
        }
    }
}

impl<E: SendableError + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            Operational(e) => Some(e),
            Timeout(e) => Some(e),
            _ => None,
        }
    }
}

// TODO split into v1 and v2 traits
pub trait Db: Clone + Send + Sync + 'static {
    type OperationalError: SendableError + 'static;

    /// Store a v2 payload.
    fn post_v2_payload(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Option<()>, Error<Self::OperationalError>>> + Send;

    /// Read a stored v1 request or v2 payload, waiting if not yet posted.
    fn wait_for_v2_payload(
        &self,
        mailbox_id: &ShortId,
    ) -> impl Future<Output = Result<Arc<Vec<u8>>, Error<Self::OperationalError>>> + Send;

    /// Write a v1 response payload.
    fn post_v1_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), Error<Self::OperationalError>>> + Send;

    /// Store a v1 request payload, waiting for any response.
    fn post_v1_request_and_wait_for_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Arc<Vec<u8>>, Error<Self::OperationalError>>> + Send;
}

#[derive(Clone, Debug)]
pub enum DbRequest {
    PostV2Payload { mailbox_id: ShortId, payload: Vec<u8> },
    WaitForV2Payload { mailbox_id: ShortId },
    PostV1Response { mailbox_id: ShortId, payload: Vec<u8> },
    PostV1RequestAndWaitForResponse { mailbox_id: ShortId, payload: Vec<u8> },
}

#[derive(Clone, Debug)]
pub enum DbResponse {
    PostV2Payload(Option<()>),
    WaitForV2Payload(Arc<Vec<u8>>),
    PostV1Response(()),
    PostV1RequestAndWaitForResponse(Arc<Vec<u8>>),
}

#[derive(Clone, Debug)]
pub struct FilesDbService {
    db: FilesDb,
}

impl FilesDbService {
    pub fn new(db: FilesDb) -> Self { Self { db } }
}

impl Service<DbRequest> for FilesDbService {
    type Response = DbResponse;
    type Error = Error<io::Error>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: DbRequest) -> Self::Future {
        let db = self.db.clone();
        Box::pin(async move {
            match request {
                DbRequest::PostV2Payload { mailbox_id, payload } =>
                    Ok(DbResponse::PostV2Payload(db.post_v2_payload(&mailbox_id, payload).await?)),
                DbRequest::WaitForV2Payload { mailbox_id } =>
                    Ok(DbResponse::WaitForV2Payload(db.wait_for_v2_payload(&mailbox_id).await?)),
                DbRequest::PostV1Response { mailbox_id, payload } => {
                    db.post_v1_response(&mailbox_id, payload).await?;
                    Ok(DbResponse::PostV1Response(()))
                }
                DbRequest::PostV1RequestAndWaitForResponse { mailbox_id, payload } =>
                    Ok(DbResponse::PostV1RequestAndWaitForResponse(
                        db.post_v1_request_and_wait_for_response(&mailbox_id, payload).await?,
                    )),
            }
        })
    }
}

#[derive(Clone)]
pub struct DbServiceAdapter {
    inner: BoxCloneSyncService<DbRequest, DbResponse, Error<io::Error>>,
}

impl DbServiceAdapter {
    pub fn new(files_db: FilesDb) -> Self {
        let service = FilesDbService::new(files_db);
        Self { inner: BoxCloneSyncService::new(service) }
    }

    fn invalid_response(operation: &str) -> Error<io::Error> {
        Error::Operational(io::Error::other(format!(
            "invalid db response for operation {operation}"
        )))
    }
}

impl Db for DbServiceAdapter {
    type OperationalError = io::Error;

    async fn post_v2_payload(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> Result<Option<()>, Error<Self::OperationalError>> {
        let response = self
            .inner
            .clone()
            .oneshot(DbRequest::PostV2Payload { mailbox_id: *mailbox_id, payload: data })
            .await?;
        match response {
            DbResponse::PostV2Payload(result) => Ok(result),
            _ => Err(Self::invalid_response("post_v2_payload")),
        }
    }

    async fn wait_for_v2_payload(
        &self,
        mailbox_id: &ShortId,
    ) -> Result<Arc<Vec<u8>>, Error<Self::OperationalError>> {
        let response = self
            .inner
            .clone()
            .oneshot(DbRequest::WaitForV2Payload { mailbox_id: *mailbox_id })
            .await?;
        match response {
            DbResponse::WaitForV2Payload(result) => Ok(result),
            _ => Err(Self::invalid_response("wait_for_v2_payload")),
        }
    }

    async fn post_v1_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        let response = self
            .inner
            .clone()
            .oneshot(DbRequest::PostV1Response { mailbox_id: *mailbox_id, payload: data })
            .await?;
        match response {
            DbResponse::PostV1Response(()) => Ok(()),
            _ => Err(Self::invalid_response("post_v1_response")),
        }
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> Result<Arc<Vec<u8>>, Error<Self::OperationalError>> {
        let response = self
            .inner
            .clone()
            .oneshot(DbRequest::PostV1RequestAndWaitForResponse {
                mailbox_id: *mailbox_id,
                payload: data,
            })
            .await?;
        match response {
            DbResponse::PostV1RequestAndWaitForResponse(result) => Ok(result),
            _ => Err(Self::invalid_response("post_v1_request_and_wait_for_response")),
        }
    }
}

pub use files::FilesDb;
