use std::fmt::{self, Display};

use super::{id, NewReceiver, Receiver};
use crate::persist::{self, Persister};
use crate::receive::ImplementationError;
use crate::uri::ShortId;

impl NewReceiver {
    /// Saves the new [`Receiver`] using the provided persister and returns the storage token.
    pub fn persist<P: Persister<Receiver>>(
        &self,
        persister: &mut P,
    ) -> Result<P::Token, ImplementationError> {
        let receiver = Receiver { context: self.context.clone() };
        Ok(persister.save(receiver)?)
    }
}

/// Opaque key type for the receiver
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverToken(ShortId);

impl Display for ReceiverToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Receiver> for ReceiverToken {
    fn from(receiver: Receiver) -> Self { ReceiverToken(id(&receiver.context.s)) }
}

impl AsRef<[u8]> for ReceiverToken {
    fn as_ref(&self) -> &[u8] { self.0.as_bytes() }
}

impl persist::Value for Receiver {
    type Key = ReceiverToken;

    fn key(&self) -> Self::Key { ReceiverToken(id(&self.context.s)) }
}

impl Receiver {
    /// Loads a [`Receiver`] from the provided persister using the storage token.
    pub fn load<P: Persister<Receiver>>(
        token: P::Token,
        persister: &P,
    ) -> Result<Self, ImplementationError> {
        persister.load(token).map_err(ImplementationError::from)
    }
}
