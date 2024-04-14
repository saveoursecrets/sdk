//! Bridge between local storage and a remote server.
use crate::client::{net::HttpClient, Error, RemoteSync, Result, SyncError};
use async_trait::async_trait;
use sos_sdk::{
    account::{Account, LocalAccount},
    commit::Comparison,
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    storage::files::{list_external_files, FileSet},
    sync::{
        self, MaybeDiff, Merge, Origin, SyncClient, SyncOptions, SyncPacket,
        SyncStatus, SyncStorage, UpdateSet,
    },
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tracing::{span, Level};

/// Collection of remote targets for synchronization.
pub(crate) type Remotes = HashMap<Origin, RemoteBridge>;

/// Bridge between a local account and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Origin for this remote.
    origin: Origin,
    /// Account so we can replay events
    /// when a remote diff is merged.
    account: Arc<Mutex<LocalAccount>>,
    /// Client to use for remote communication.
    pub(crate) client: HttpClient,
}

impl RemoteBridge {
    /// Create a new remote bridge that updates the given
    /// local account.
    pub fn new(
        account: Arc<Mutex<LocalAccount>>,
        origin: Origin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        connection_id: String,
    ) -> Result<Self> {
        let client =
            HttpClient::new(origin.clone(), signer, device, connection_id)?;
        Ok(Self {
            account,
            origin,
            client,
        })
    }

    /// Client implementation.
    pub fn client(&self) -> &HttpClient {
        &self.client
    }
}

/// Sync helper functions.
impl RemoteBridge {
    /// Create an account on the remote.
    async fn create_remote_account(&self) -> Result<()> {
        {
            let account = self.account.lock().await;
            let public_account = account.change_set().await?;
            self.client.create_account(&public_account).await?;
        }
        self.execute_sync_file_transfers().await?;
        Ok(())
    }

    async fn sync_account(&self, remote_status: SyncStatus) -> Result<()> {
        let mut account = self.account.lock().await;

        let (needs_sync, local_status, local_changes) =
            sync::diff(&*account, remote_status).await?;

        tracing::debug!(needs_sync = %needs_sync);

        if needs_sync {
            let span = span!(Level::DEBUG, "merge_client");
            let _enter = span.enter();
            let packet = SyncPacket {
                status: local_status,
                diff: local_changes,
                compare: None,
            };
            let remote_changes = self.client.sync(&packet).await?;
            account.merge(&remote_changes.diff).await?;

            self.compare(&mut *account, remote_changes).await?;
        }

        Ok(())
    }

    /// Compare the remote comparison with the local
    /// comparison and determine if a force pull or automerge
    /// is required.
    async fn compare(
        &self,
        account: &mut LocalAccount,
        remote_changes: SyncPacket,
    ) -> Result<()> {
        if let Some(remote_compare) = &remote_changes.compare {
            // println!("{:#?}", remote_changes);

            let local_compare =
                account.compare(&remote_changes.status).await?;

            // NOTE: we don't currently handle account, device and
            // NOTE: files here as they are currently append-only.
            // NOTE: if later we support compacting these event logs
            // NOTE: we need to handle force pull here.

            match (&local_compare.identity, &remote_compare.identity) {
                (Some(Comparison::Unknown), Some(Comparison::Unknown)) => {
                    println!(
                        "todo!: handle completely diverged identity folder"
                    );
                }
                _ => {}
            }

            // NOTE: we don't need to handle folders here as
            // NOTE: destructive changes should call
            // NOTE: import_folder_buffer() which generates
            // NOTE: an AccountEvent::UpdateVault event which
            // NOTE: will be handled and automatically rewrite
            // NOTE: the content of the folder
        }

        Ok(())
    }

    async fn execute_sync(&self) -> Result<()> {
        let sync_status = self.client.sync_status().await?;
        if let Some(sync_status) = sync_status {
            self.sync_account(sync_status).await
        } else {
            self.create_remote_account().await
        }
    }

    async fn send_devices_patch(
        &self,
        remote_status: SyncStatus,
    ) -> Result<()> {
        let (needs_sync, _local_status, local_changes) = {
            let account = self.account.lock().await;
            sync::diff(&*account, remote_status).await?
        };

        // If we need a sync but no local device changes
        // try to pull from remote
        if let (true, None) = (needs_sync, &local_changes.device) {
            self.execute_sync().await?;
        }

        #[cfg(feature = "device")]
        if let (true, Some(MaybeDiff::Diff(device))) =
            (needs_sync, local_changes.device)
        {
            self.client.patch_devices(&device).await?;
        }
        Ok(())
    }

    async fn execute_sync_devices(&self) -> Result<()> {
        let sync_status = self.client.sync_status().await?;
        if let Some(sync_status) = sync_status {
            self.send_devices_patch(sync_status).await
        } else {
            Err(Error::NoAccountPatchDevices)
        }
    }

    async fn execute_sync_file_transfers(&self) -> Result<()> {
        let paths = {
            let account = self.account.lock().await;
            account.paths()
        };

        let external_files = list_external_files(&*paths).await?;
        let file_set = FileSet(external_files);
        let file_transfers = self.client.compare_files(&file_set).await?;

        {
            let account = self.account.lock().await;
            let transfers = account.transfers().await?;
            let mut transfers = transfers.write().await;
            transfers.merge_file_transfers(file_transfers).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl RemoteSync for RemoteBridge {
    async fn sync(&self) -> Option<SyncError> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        let should_sync = options.origins.is_empty()
            || options
                .origins
                .iter()
                .find(|&o| o == &self.origin)
                .is_some();

        if !should_sync {
            tracing::warn!(origin = %self.origin, "skip sync");
            return None;
        }

        tracing::debug!(origin = %self.origin.url());

        match self.execute_sync().await {
            Ok(_) => None,
            Err(e) => Some(SyncError {
                errors: vec![(self.origin.clone(), e)],
            }),
        }
    }

    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        let should_sync = options.origins.is_empty()
            || options
                .origins
                .iter()
                .find(|&o| o == &self.origin)
                .is_some();

        if !should_sync {
            tracing::warn!(origin = %self.origin, "skip sync");
            return None;
        }

        tracing::debug!(origin = %self.origin.url());

        match self.execute_sync_file_transfers().await {
            Ok(_) => None,
            Err(e) => Some(SyncError {
                errors: vec![(self.origin.clone(), e)],
            }),
        }
    }

    async fn patch_devices(
        &self,
        _options: &SyncOptions,
    ) -> Option<SyncError> {
        match self.execute_sync_devices().await {
            Ok(_) => None,
            Err(e) => Some(SyncError {
                errors: vec![(self.origin.clone(), e)],
            }),
        }
    }

    async fn force_update(
        &self,
        account_data: &UpdateSet,
        _options: &SyncOptions,
    ) -> Option<SyncError> {
        match self.client.update_account(account_data).await {
            Ok(_) => None,
            Err(e) => Some(SyncError {
                errors: vec![(self.origin.clone(), e)],
            }),
        }
    }
}

#[cfg(feature = "listen")]
mod listen {
    use crate::{
        client::{
            sync::RemoteSync, ListenOptions, RemoteBridge, Result,
            WebSocketHandle,
        },
        ChangeNotification,
    };

    use std::sync::Arc;

    // Listen to change notifications and attempt to sync.
    #[cfg(not(target_arch = "wasm32"))]
    impl RemoteBridge {
        async fn on_change_notification(
            bridge: Arc<RemoteBridge>,
            _change: ChangeNotification,
        ) -> Result<()> {
            if let Some(e) = bridge.sync().await {
                tracing::error!(
                    error = ?e,
                    "listen change sync failed",
                );
            }
            Ok(())
        }

        /// Spawn a task that listens for changes
        /// from the remote server and applies any changes
        /// from the remote to the local account.
        ///
        /// The keypair for the websocket connection must not be
        /// the same as the main client so you should always generate
        /// a new keypair for this connection. Otherwise transports
        /// will collide on the server as they are identified by
        /// public key.
        pub(crate) fn listen(
            bridge: Arc<RemoteBridge>,
            options: ListenOptions,
        ) -> WebSocketHandle {
            let remote_bridge = Arc::clone(&bridge);
            let handle = bridge.client.listen(options, move |notification| {
                let bridge = Arc::clone(&remote_bridge);
                async move {
                    tracing::debug!(notification = ?notification);
                    if let Err(e) =
                        Self::on_change_notification(bridge, notification)
                            .await
                    {
                        tracing::error!(error = ?e);
                    }
                }
            });

            handle
        }
    }
}
