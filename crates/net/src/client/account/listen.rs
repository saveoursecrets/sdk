//! Adds functions for listening to change notifications using
//! a websocket connection.
use crate::{
    client::{
        sync::RemoteSync, Error, ListenOptions, NetworkAccount, Result,
        WebSocketHandle,
    },
    sdk::sync::{Origin, SyncError},
    ChangeNotification,
};
use std::sync::Arc;
use tokio::sync::mpsc;

impl NetworkAccount {
    /// Listen for changes on a remote server.
    pub async fn listen(
        &self,
        origin: &Origin,
        options: ListenOptions,
        listener: Option<
            mpsc::Sender<(ChangeNotification, Option<SyncError<Error>>)>,
        >,
    ) -> Result<WebSocketHandle> {
        let remotes = self.remotes.read().await;
        if let Some(remote) = remotes.get(origin) {
            let remote = Arc::new(remote.clone());

            let (tx, mut rx) = mpsc::channel::<ChangeNotification>(32);

            let sync_lock = Arc::clone(&self.sync_lock);
            let sync_remote = Arc::clone(&remote);

            tokio::task::spawn(async move {
                while let Some(message) = rx.recv().await {
                    // If the change notification has changes
                    // then we attempt to sync with the remote
                    if message.outcome().changes > 0 {
                        // Ensure we acquire the sync lock
                        // to prevent other changes to the storage
                        let _ = sync_lock.lock().await;

                        // Sync with the remote that notified us
                        let sync_error = sync_remote.sync().await;
                        if let Some(e) = &sync_error {
                            tracing::error!(
                                error = ?e,
                                "listen_sync",
                            );
                        }

                        // If we have a listener notify them with the
                        // change notification and a possible sync error
                        let tx = listener.clone();
                        if let Some(tx) = tx {
                            let _ = tx.send((message, sync_error)).await;
                        }
                    }
                }
            });

            let handle = remote.listen(options, tx);

            // Store the listeners so we can
            // close the connections on sign out
            let mut listeners = self.listeners.lock().await;
            listeners.push(handle.clone());

            Ok(handle)
        } else {
            Err(Error::OriginNotFound(origin.clone()))
        }
    }
}
