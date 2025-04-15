use std::fmt::{self, Display};

use super::{id, Receiver};
use crate::persist::{self};
use crate::uri::ShortId;

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
