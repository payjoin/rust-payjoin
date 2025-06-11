use crate::persist::{self, Persister};
use crate::send::multiparty::{ImplementationError, NewSender, Sender};
use crate::send::v2::{self, SenderToken};

impl NewSender {
    pub fn persist<P: Persister<Sender>>(
        &self,
        persister: &mut P,
    ) -> Result<P::Token, ImplementationError> {
        let sender = Sender(v2::Sender {
            state: v2::WithReplyKey { v1: self.0.v1.clone(), reply_key: self.0.reply_key.clone() },
        });
        persister.save(sender).map_err(ImplementationError::from)
    }
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
