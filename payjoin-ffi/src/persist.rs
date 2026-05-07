//! In-memory implementations of the JSON session persister traits exposed by
//! [`crate::receive`] and [`crate::send`].
//!
//! These wrap [`payjoin::persist::InMemoryPersister`] so that bindings can use a
//! ready-made persister for tests, examples, and prototyping without having to
//! re-implement the same event log in every language.
//!
//! Each wrapper exposes an `as_persister` method that returns the corresponding
//! `Arc<dyn Trait>`. uniffi 0.31 generates separate types for `uniffi::Object`
//! classes and `with_foreign` callback interfaces, and statically-typed bindings
//! (Dart, C#) will not accept the class where the interface is expected. The
//! conversion method is the upstream-recommended workaround tracked in
//! <https://github.com/mozilla/uniffi-rs/issues/2542>.

use std::sync::Arc;

use payjoin::persist::{AsyncSessionPersister, InMemoryPersister, SessionPersister};

use crate::error::ForeignError;
use crate::receive::ReceiverSessionEvent;
use crate::send::SenderSessionEvent;

/// Session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
pub trait JsonReceiverSessionPersister: Send + Sync {
    fn save(&self, event: String) -> Result<(), ForeignError>;
    fn load(&self) -> Result<Vec<String>, ForeignError>;
    fn close(&self) -> Result<(), ForeignError>;
}

/// Async session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait JsonReceiverSessionPersisterAsync: Send + Sync {
    async fn save(&self, event: String) -> Result<(), ForeignError>;
    async fn load(&self) -> Result<Vec<String>, ForeignError>;
    async fn close(&self) -> Result<(), ForeignError>;
}

/// Session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
pub trait JsonSenderSessionPersister: Send + Sync {
    fn save(&self, event: String) -> Result<(), ForeignError>;
    fn load(&self) -> Result<Vec<String>, ForeignError>;
    fn close(&self) -> Result<(), ForeignError>;
}

/// Async session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait JsonSenderSessionPersisterAsync: Send + Sync {
    async fn save(&self, event: String) -> Result<(), ForeignError>;
    async fn load(&self) -> Result<Vec<String>, ForeignError>;
    async fn close(&self) -> Result<(), ForeignError>;
}

/// In-memory [`JsonReceiverSessionPersister`] backed by
/// [`payjoin::persist::InMemoryPersister`].
#[derive(uniffi::Object, Default)]
pub struct InMemoryReceiverPersister(InMemoryPersister<String>);

#[uniffi::export]
impl InMemoryReceiverPersister {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    /// Returns this persister as a [`JsonReceiverSessionPersister`] trait object so it can
    /// be passed to APIs that take a callback persister.
    pub fn as_persister(self: Arc<Self>) -> Arc<dyn JsonReceiverSessionPersister> { self }
}

impl JsonReceiverSessionPersister for InMemoryReceiverPersister {
    fn save(&self, event: String) -> Result<(), ForeignError> {
        self.0.save_event(event).expect("InMemoryPersister save_event is infallible");
        Ok(())
    }

    fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.0.load().expect("InMemoryPersister load is infallible").collect())
    }

    fn close(&self) -> Result<(), ForeignError> {
        self.0.close().expect("InMemoryPersister close is infallible");
        Ok(())
    }
}

/// Async in-memory [`JsonReceiverSessionPersisterAsync`] backed by
/// [`payjoin::persist::InMemoryPersister`].
///
/// The trait methods are `async`-shaped but the storage layer is synchronous: they exist
/// so binding tests can exercise the async save/load/close FFI dispatch path, not to
/// model real I/O.
#[derive(uniffi::Object, Default)]
pub struct InMemoryReceiverPersisterAsync(InMemoryPersister<String>);

#[uniffi::export]
impl InMemoryReceiverPersisterAsync {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    /// Returns this persister as a [`JsonReceiverSessionPersisterAsync`] trait object so it
    /// can be passed to APIs that take a callback persister.
    pub fn as_persister(self: Arc<Self>) -> Arc<dyn JsonReceiverSessionPersisterAsync> { self }
}

#[async_trait::async_trait]
impl JsonReceiverSessionPersisterAsync for InMemoryReceiverPersisterAsync {
    async fn save(&self, event: String) -> Result<(), ForeignError> {
        self.0.save_event(event).expect("InMemoryPersister save_event is infallible");
        Ok(())
    }

    async fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.0.load().expect("InMemoryPersister load is infallible").collect())
    }

    async fn close(&self) -> Result<(), ForeignError> {
        self.0.close().expect("InMemoryPersister close is infallible");
        Ok(())
    }
}

/// In-memory [`JsonSenderSessionPersister`] backed by
/// [`payjoin::persist::InMemoryPersister`].
#[derive(uniffi::Object, Default)]
pub struct InMemorySenderPersister(InMemoryPersister<String>);

#[uniffi::export]
impl InMemorySenderPersister {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    /// Returns this persister as a [`JsonSenderSessionPersister`] trait object so it can be
    /// passed to APIs that take a callback persister.
    pub fn as_persister(self: Arc<Self>) -> Arc<dyn JsonSenderSessionPersister> { self }
}

impl JsonSenderSessionPersister for InMemorySenderPersister {
    fn save(&self, event: String) -> Result<(), ForeignError> {
        self.0.save_event(event).expect("InMemoryPersister save_event is infallible");
        Ok(())
    }

    fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.0.load().expect("InMemoryPersister load is infallible").collect())
    }

    fn close(&self) -> Result<(), ForeignError> {
        self.0.close().expect("InMemoryPersister close is infallible");
        Ok(())
    }
}

/// Async in-memory [`JsonSenderSessionPersisterAsync`] backed by
/// [`payjoin::persist::InMemoryPersister`].
///
/// The trait methods are `async`-shaped but the storage layer is synchronous: they exist
/// so binding tests can exercise the async save/load/close FFI dispatch path, not to
/// model real I/O.
#[derive(uniffi::Object, Default)]
pub struct InMemorySenderPersisterAsync(InMemoryPersister<String>);

#[uniffi::export]
impl InMemorySenderPersisterAsync {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    /// Returns this persister as a [`JsonSenderSessionPersisterAsync`] trait object so it
    /// can be passed to APIs that take a callback persister.
    pub fn as_persister(self: Arc<Self>) -> Arc<dyn JsonSenderSessionPersisterAsync> { self }
}

#[async_trait::async_trait]
impl JsonSenderSessionPersisterAsync for InMemorySenderPersisterAsync {
    async fn save(&self, event: String) -> Result<(), ForeignError> {
        self.0.save_event(event).expect("InMemoryPersister save_event is infallible");
        Ok(())
    }

    async fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.0.load().expect("InMemoryPersister load is infallible").collect())
    }

    async fn close(&self) -> Result<(), ForeignError> {
        self.0.close().expect("InMemoryPersister close is infallible");
        Ok(())
    }
}

/// Adapter for the [`JsonReceiverSessionPersister`] trait to use the save and load callbacks.
pub(crate) struct ReceiverCallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonReceiverSessionPersister>,
}

impl ReceiverCallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonReceiverSessionPersister>) -> Self {
        Self { callback_persister }
    }
}

impl SessionPersister for ReceiverCallbackPersisterAdapter {
    type SessionEvent = payjoin::receive::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let uni_event: ReceiverSessionEvent = event.into();
        self.callback_persister
            .save(uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?)
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let res = self.callback_persister.load()?;
        let events = res
            .into_iter()
            .map(|event| {
                ReceiverSessionEvent::from_json(event)
                    .map_err(|e| ForeignError::InternalError(e.to_string()))
                    .map(|e| e.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { self.callback_persister.close() }
}

/// Adapter for the [`JsonReceiverSessionPersisterAsync`] trait to use the save and load callbacks.
pub(crate) struct AsyncReceiverCallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonReceiverSessionPersisterAsync>,
}

impl AsyncReceiverCallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonReceiverSessionPersisterAsync>) -> Self {
        Self { callback_persister }
    }
}

impl AsyncSessionPersister for AsyncReceiverCallbackPersisterAdapter {
    type SessionEvent = payjoin::receive::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let uni_event: ReceiverSessionEvent = event.into();
        let persister = self.callback_persister.clone();
        async move {
            let json =
                uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?;
            persister.save(json).await
        }
    }

    fn load(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
            Self::InternalStorageError,
        >,
    > + Send {
        let persister = self.callback_persister.clone();
        async move {
            let res = persister.load().await?;
            let events: Vec<_> = res
                .into_iter()
                .map(|event| {
                    ReceiverSessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(Into::into)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Box::new(events.into_iter()) as Box<dyn Iterator<Item = _> + Send>)
        }
    }

    fn close(
        &self,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let persister = self.callback_persister.clone();
        async move { persister.close().await }
    }
}

/// Adapter for the [`JsonSenderSessionPersister`] trait to use the save and load callbacks.
pub(crate) struct SenderCallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonSenderSessionPersister>,
}

impl SenderCallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonSenderSessionPersister>) -> Self {
        Self { callback_persister }
    }
}

impl SessionPersister for SenderCallbackPersisterAdapter {
    type SessionEvent = payjoin::send::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let event: SenderSessionEvent = event.into();
        self.callback_persister
            .save(event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?)
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let res = self.callback_persister.load()?;
        let events = res
            .into_iter()
            .map(|event| {
                SenderSessionEvent::from_json(event)
                    .map_err(|e| ForeignError::InternalError(e.to_string()))
                    .map(|e| e.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { self.callback_persister.close() }
}

/// Adapter for the [`JsonSenderSessionPersisterAsync`] trait to use the save and load callbacks.
pub(crate) struct AsyncSenderCallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonSenderSessionPersisterAsync>,
}

impl AsyncSenderCallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonSenderSessionPersisterAsync>) -> Self {
        Self { callback_persister }
    }
}

impl AsyncSessionPersister for AsyncSenderCallbackPersisterAdapter {
    type SessionEvent = payjoin::send::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let uni_event: SenderSessionEvent = event.into();
        let persister = self.callback_persister.clone();
        async move {
            let json =
                uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?;
            persister.save(json).await
        }
    }

    fn load(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
            Self::InternalStorageError,
        >,
    > + Send {
        let persister = self.callback_persister.clone();
        async move {
            let res = persister.load().await?;
            let events: Vec<_> = res
                .into_iter()
                .map(|event| {
                    SenderSessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(Into::into)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Box::new(events.into_iter()) as Box<dyn Iterator<Item = _> + Send>)
        }
    }

    fn close(
        &self,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let persister = self.callback_persister.clone();
        async move { persister.close().await }
    }
}
