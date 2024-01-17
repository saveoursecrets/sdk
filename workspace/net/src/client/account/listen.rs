//! Adds functions for listening to change notifications using
//! a websocket connection.
use crate::{
    client::{
        Error, ListenOptions, NetworkAccount, RemoteBridge, Result,
        WebSocketHandle,
    },
    sdk::sync::Origin,
};
use std::sync::Arc;

impl NetworkAccount {
    /// Listen for changes on a remote origin.
    pub async fn listen(
        &self,
        origin: &Origin,
        options: ListenOptions,
    ) -> Result<WebSocketHandle> {
        let remotes = self.remotes.read().await;
        if let Some(remote) = remotes.get(origin) {
            if let Some(remote) =
                remote.as_any().downcast_ref::<RemoteBridge>()
            {
                let remote = Arc::new(remote.clone());
                let handle = RemoteBridge::listen(remote, options);

                // Store the listeners so we can
                // close the connections on sign out
                let mut listeners = self.listeners.lock().await;
                listeners.push(handle.clone());

                Ok(handle)
            } else {
                unreachable!();
            }
        } else {
            Err(Error::OriginNotFound(origin.clone()))
        }
    }
}
