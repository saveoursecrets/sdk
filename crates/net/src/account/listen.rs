//! Adds functions for listening to change notifications using
//! a websocket connection.
use crate::{
    protocol::{ChangeNotification, Origin, SyncError, SyncStorage},
    sync::RemoteSync,
    Error, ListenOptions, NetworkAccount, Result,
};
use std::sync::Arc;
use tokio::sync::mpsc;

impl NetworkAccount {
    /// Close all the websocket connections.
    #[cfg(feature = "listen")]
    pub(super) async fn shutdown_websockets(&self) {
        tracing::debug!("listen::close_all_websockets");

        let mut listeners = self.listeners.lock().await;
        for (_, handle) in listeners.drain() {
            handle.close().await;
        }
    }

    /// Stop listening to a server websocket.
    pub async fn stop_listening(&self, origin: &Origin) {
        let mut listeners = self.listeners.lock().await;
        if let Some(handle) = listeners.get(origin) {
            tracing::debug!(
                url = %origin.url(),
                "listen::close_websocket");

            handle.close().await;
            listeners.remove(origin);
        }
    }
    /// Listen for changes on a server websocket.
    pub async fn listen(
        &self,
        origin: &Origin,
        options: ListenOptions,
        listener: Option<
            mpsc::Sender<(ChangeNotification, Option<SyncError<Error>>)>,
        >,
    ) -> Result<()> {
        let remotes = self.remotes.read().await;
        if let Some(remote) = remotes.get(origin) {
            self.stop_listening(&origin).await;

            let remote = Arc::new(remote.clone());
            let (tx, mut rx) = mpsc::channel::<ChangeNotification>(32);

            let local_account = Arc::clone(&self.account);
            let sync_lock = Arc::clone(&self.sync_lock);
            let sync_remote = Arc::clone(&remote);

            tokio::task::spawn(async move {
                while let Some(message) = rx.recv().await {
                    // If the change notification has changes
                    // then we attempt to sync with the remote
                    if message.outcome().changes > 0 {
                        // When multiple servers are configured and we
                        // are listening for notifications to multiple
                        // servers then this will fire for each server
                        // however it's likely the same change set is
                        // being applied to all servers. By comparing
                        // the cumulative root hashes against our local
                        // status we can drop change notifications that
                        // would not make any changes which will reduce
                        // network traffic and prevent multiple re-renders
                        // in the UI.
                        let differs = {
                            let account = local_account.lock().await;
                            let local_status = account.sync_status().await?;
                            &local_status.root != message.root()
                        };

                        if differs {
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
                        } else {
                            tracing::debug!(
                              root = %message.root(),
                              "drop_change_notification",
                            );
                        }
                    }
                }

                Ok::<(), Error>(())
            });

            let handle = remote.listen(options, tx);

            // Store the listeners so we can
            // close the connections on sign out
            {
                let mut listeners = self.listeners.lock().await;
                listeners.insert(origin.clone(), handle);
            }

            Ok(())
        } else {
            Err(Error::OriginNotFound(origin.clone()))
        }
    }
}
