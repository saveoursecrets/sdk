//! Adds functions for listening to change notifications using
//! a websocket connection.
use crate::client::{
    account::remote::{NetworkAccountReceiver, NetworkAccountSender},
    Error, ListenOptions, NetworkAccount, Origin, RemoteBridge, Result,
    WebSocketHandle,
};
use futures::{select, FutureExt};
use sos_sdk::prelude::SecureAccessKey;
use std::sync::Arc;

use super::network_account::LocalAccount;

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
                let (handle, rx, tx) = RemoteBridge::listen(remote, options);
                self.spawn_remote_bridge_channels(rx, tx);

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

    fn spawn_remote_bridge_channels(
        &self,
        mut rx: NetworkAccountReceiver,
        tx: NetworkAccountSender,
    ) {
        if self.account.is_authenticated() {
            let user = self.user().unwrap();
            let keeper = user.identity().keeper();
            let secret_key = user.identity().signer().to_bytes();

            // TODO: needs shutdown hook so this loop exits
            // TODO: when the websocket connection is closed
            tokio::task::spawn(async move {
                loop {
                    select!(
                        event = rx
                            .secure_access_key_rx
                            .recv()
                            .fuse() => {
                            if let Some((folder_id, secure_key)) = event {

                                // Decrypt the secure access key received
                                // when creating or importing a folder,
                                // must be done here as the remote bridge
                                // does not have access to the private key
                                // (account signing key)
                                let access_key = SecureAccessKey::decrypt(
                                    &secure_key,
                                    secret_key.clone(),
                                )
                                .await?;

                                // Save the access key for the synced folder
                                let identity = Arc::clone(&keeper);
                                LocalAccount::save_folder_password(
                                    identity,
                                    &folder_id,
                                    access_key.clone(),
                                )
                                .await?;

                                tx.access_key_tx.send(access_key).await?;
                            }
                        }
                        event = rx
                            .remove_vault_rx
                            .recv()
                            .fuse() => {
                            if let Some(folder_id) = event {
                                // When a folder is removed via remote
                                // bridge changes we need to clean up the
                                // passphrase
                                let identity = Arc::clone(&keeper);
                                LocalAccount::remove_folder_password(
                                    identity,
                                    &folder_id,
                                )
                                .await?;
                            }
                        }
                    )
                }
                Ok::<(), Error>(())
            });
        }
    }
}
