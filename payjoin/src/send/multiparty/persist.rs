use std::fmt::{self, Display};

use url::Url;

use crate::persist::{self, Persister};
use crate::send::multiparty::{ImplementationError, NewSender, Sender};
use crate::send::v2;

impl NewSender {
    pub fn persist<P: Persister<Sender>>(
        &self,
        persister: &mut P,
    ) -> Result<P::Token, ImplementationError> {
        let sender =
            Sender(v2::Sender { v1: self.0.v1.clone(), reply_key: self.0.reply_key.clone() });
        persister.save(sender).map_err(ImplementationError::from)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderToken(Url);

impl Display for SenderToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Sender> for SenderToken {
    fn from(sender: Sender) -> Self { SenderToken(sender.0.endpoint().clone()) }
}

impl AsRef<[u8]> for SenderToken {
    fn as_ref(&self) -> &[u8] { self.0.as_str().as_bytes() }
}

impl persist::Value for Sender {
    type Key = SenderToken;

    fn key(&self) -> Self::Key { SenderToken(self.0.endpoint().clone()) }
}

impl Sender {
    pub fn load<P: Persister<Sender>>(
        token: P::Token,
        persister: &P,
) -> Result<Self, ImplementationError> {
        let sender = persister.load(token).map_err(ImplementationError::from)?;
        Ok(sender)
    }
}
