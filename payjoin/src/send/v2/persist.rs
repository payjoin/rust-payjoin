use std::fmt::{self, Display};

use url::Url;

use super::Sender;
use crate::persist::Value;

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
