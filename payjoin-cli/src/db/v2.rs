use std::sync::Arc;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::persist::{PersistableValue, Persister};
use payjoin::receive::v2::Receiver;
use payjoin::send::v2::Sender;
use sled::Tree;
use url::Url;

use super::*;

#[derive(Clone)]
pub(crate) struct SenderPersister(pub Arc<Database>);
impl Persister<Sender> for SenderPersister {
    type Error = crate::db::error::Error;
    fn save(&mut self, value: Sender) -> std::result::Result<String, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let token = value.key();
        let value = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        send_tree.insert(token.clone(), value.as_slice())?;
        send_tree.flush()?;
        Ok(token)
    }

    fn load(&self, token: &str) -> std::result::Result<Sender, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let value = send_tree.get(token)?.ok_or(Error::NotFound(token.to_string()))?;
        serde_json::from_slice(&value).map_err(Error::Deserialize)
    }
}

#[derive(Clone)]
pub(crate) struct ReceiverPersister(pub Arc<Database>);
impl Persister<Receiver> for ReceiverPersister {
    type Error = crate::db::error::Error;
    fn save(&mut self, value: Receiver) -> std::result::Result<String, Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let key = value.key();
        let value = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        recv_tree.insert(key.clone(), value.as_slice())?;
        recv_tree.flush()?;
        Ok(key)
    }
    fn load(&self, token: &str) -> std::result::Result<Receiver, Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let value = recv_tree.get(token)?.ok_or(Error::NotFound(token.to_string()))?;
        serde_json::from_slice(&value).map_err(Error::Deserialize)
    }
}

impl Database {
    pub(crate) fn get_recv_sessions(&self) -> Result<Vec<Receiver>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let session: Receiver = serde_json::from_slice(&value).map_err(Error::Deserialize)?;
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
