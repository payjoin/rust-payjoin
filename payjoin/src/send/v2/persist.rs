use std::fmt::{self, Display};

use url::Url;

use super::{ImplementationError, NewSender, Sender};
use crate::persist::{Persister, Value};
impl NewSender {
    /// Saves the new [`Sender`] using the provided persister and returns the storage token.
    pub fn persist<P: Persister<Sender>>(
        &self,
        persister: &mut P,
    ) -> Result<P::Token, ImplementationError> {
        let sender = Sender { v1: self.v1.clone(), reply_key: self.reply_key.clone() };
        Ok(persister.save(sender)?)
    }
}

/// Opaque key type for the sender
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderToken(pub(crate) Url);

impl Display for SenderToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Sender> for SenderToken {
    fn from(sender: Sender) -> Self { SenderToken(sender.endpoint().clone()) }
}

impl AsRef<[u8]> for SenderToken {
    fn as_ref(&self) -> &[u8] { self.0.as_str().as_bytes() }
}

impl Value for Sender {
    type Key = SenderToken;

    fn key(&self) -> Self::Key { SenderToken(self.endpoint().clone()) }
}

impl Sender {
    /// Loads a [`Sender`] from the provided persister using the storage token.
    pub fn load<P: Persister<Sender>>(
        token: P::Token,
        persister: &P,
    ) -> Result<Self, ImplementationError> {
        persister.load(token).map_err(ImplementationError::from)
    }
}
