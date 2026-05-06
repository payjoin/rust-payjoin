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

use payjoin::persist::{InMemoryPersister, SessionPersister};

use crate::error::ForeignError;
use crate::receive::{JsonReceiverSessionPersister, JsonReceiverSessionPersisterAsync};
use crate::send::{JsonSenderSessionPersister, JsonSenderSessionPersisterAsync};

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
