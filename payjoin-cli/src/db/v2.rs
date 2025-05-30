use std::sync::Arc;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::persist::{Persister, Value};
use payjoin::receive::v2::{Receiver, ReceiverToken, WithContext};
use payjoin::send::v2::{Sender, SenderToken};
use sled::Tree;
use url::Url;

use super::*;

pub(crate) struct SenderPersister(Arc<Database>);
impl SenderPersister {
    pub fn new(db: Arc<Database>) -> Self { Self(db) }
}

impl Persister<Sender> for SenderPersister {
    type Token = SenderToken;
    type Error = crate::db::error::Error;
    fn save(&mut self, value: Sender) -> std::result::Result<SenderToken, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let key = value.key();
        let value = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        send_tree.insert(key.clone(), value.as_slice())?;
        send_tree.flush()?;
        Ok(key)
    }

    fn load(&self, key: SenderToken) -> std::result::Result<Sender, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let value = send_tree.get(key.as_ref())?.ok_or(Error::NotFound(key.to_string()))?;
        serde_json::from_slice(&value).map_err(Error::Deserialize)
    }
}

pub(crate) struct ReceiverPersister(Arc<Database>);
impl ReceiverPersister {
    pub fn new(db: Arc<Database>) -> Self { Self(db) }
}

impl Persister<Receiver<WithContext>> for ReceiverPersister {
    type Token = ReceiverToken;
    type Error = crate::db::error::Error;
    fn save(
        &mut self,
        value: Receiver<WithContext>,
    ) -> std::result::Result<ReceiverToken, Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let key = value.key();
        let value = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        recv_tree.insert(key.clone(), value.as_slice())?;
        recv_tree.flush()?;
        Ok(key)
    }
    fn load(&self, key: ReceiverToken) -> std::result::Result<Receiver<WithContext>, Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let value = recv_tree.get(key.as_ref())?.ok_or(Error::NotFound(key.to_string()))?;
        serde_json::from_slice(&value).map_err(Error::Deserialize)
    }
}

impl Database {
    pub(crate) fn get_recv_sessions(&self) -> Result<Vec<Receiver<WithContext>>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let session: Receiver<WithContext> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn clear_recv_session(&self) -> Result<()> {
        let recv_tree: Tree = self.0.open_tree("recv_sessions")?;
        recv_tree.clear()?;
        recv_tree.flush()?;
        Ok(())
    }

    pub(crate) fn get_send_sessions(&self) -> Result<Vec<Sender>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let session: Sender = serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn get_send_session(&self, pj_url: &Url) -> Result<Option<Sender>> {
        let send_tree = self.0.open_tree("send_sessions")?;
        if let Some(val) = send_tree.get(pj_url.as_str())? {
            let session: Sender = serde_json::from_slice(&val).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_send_session(&self, pj_url: &Url) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        send_tree.remove(pj_url.as_str())?;
        send_tree.flush()?;
        Ok(())
    }
}
