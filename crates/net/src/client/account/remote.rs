//! Bridge between local storage and a remote server.
use crate::client::{
    net::HttpClient, Error, RemoteSync, Result, SyncClient, SyncError,
};
use async_trait::async_trait;
use sos_sdk::{
    account::{Account, LocalAccount},
    commit::Comparison,
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    storage::{
        files::{FileSet, TransferOperation},
        StorageEventLogs,
    },
    sync::{
        self, MaybeDiff, Merge, Origin, SyncOptions, SyncPacket, SyncStatus,
        SyncStorage, UpdateSet,
    },
    vfs,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, Mutex};

#[cfg(feature = "files")]
use super::file_transfers::FileTransferQueueRequest;

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
    // File transfers.
    #[cfg(feature = "files")]
    pub(crate) file_transfer_queue:
        broadcast::Sender<FileTransferQueueRequest>,
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

        let (file_transfer_queue, _) =
            broadcast::channel::<FileTransferQueueRequest>(32);

        Ok(Self {
            account,
            origin,
            client,
            #[cfg(feature = "files")]
            file_transfer_queue,
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

        tracing::debug!("merge_client");

        let (needs_sync, local_status, local_changes) =
            sync::diff(&*account, remote_status).await?;

        tracing::debug!(needs_sync = %needs_sync, "merge_client");

        if needs_sync {
            let packet = SyncPacket {
                status: local_status,
                diff: local_changes,
                compare: None,
            };
            let remote_changes = self.client.sync(&packet).await?;

            let maybe_conflict = remote_changes
                .compare
                .as_ref()
                .map(|c| c.maybe_conflict())
                .unwrap_or_default();
            let has_conflicts = maybe_conflict.has_conflicts();

            println!(
                "remote_changes::has_conflicts {:#?}",
                maybe_conflict.has_conflicts()
            );

            if !has_conflicts {
                let (mut outcome, _) =
                    account.merge(&remote_changes.diff).await?;

                // Compute which external files need to be downloaded
                // and add to the transfers queue
                if !outcome.external_files.is_empty() {
                    let paths = account.paths();
                    // let mut writer = self.transfers.write().await;

                    for file in outcome.external_files.drain(..) {
                        let file_path = paths.file_location(
                            file.vault_id(),
                            file.secret_id(),
                            file.file_name().to_string(),
                        );
                        if !vfs::try_exists(file_path).await? {
                            tracing::debug!(
                                file = ?file,
                                "add file download to transfers",
                            );
                            if self.file_transfer_queue.receiver_count() > 0 {
                                let _ =
                                    self.file_transfer_queue.send(vec![(
                                        file,
                                        TransferOperation::Download,
                                    )]);
                            }
                        }
                    }
                }

                self.compare(&mut *account, remote_changes).await?;
            } else {
                panic!("has_conflicts");
            }
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
        let exists = self.client.account_exists().await?;
        if exists {
            let sync_status = self.client.sync_status().await?;
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
        let exists = self.client.account_exists().await?;
        if exists {
            let sync_status = self.client.sync_status().await?;
            self.send_devices_patch(sync_status).await
        } else {
            Err(Error::NoAccountPatchDevices)
        }
    }

    async fn execute_sync_file_transfers(&self) -> Result<()> {
        let external_files = {
            let account = self.account.lock().await;
            account.canonical_files().await?
        };

        let file_set = FileSet(external_files);
        let file_transfers = self.client.compare_files(&file_set).await?;

        let mut ops = Vec::new();
        for file in file_transfers.uploads.0 {
            ops.push((file, TransferOperation::Upload));
        }

        for file in file_transfers.downloads.0 {
            ops.push((file, TransferOperation::Download));
        }

        if !ops.is_empty() && self.file_transfer_queue.receiver_count() > 0 {
            let _ = self.file_transfer_queue.send(ops);
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
        client::{ListenOptions, RemoteBridge, WebSocketHandle},
        ChangeNotification,
    };
    use tokio::sync::mpsc;

    // Listen to change notifications and attempt to sync.
    #[cfg(not(target_arch = "wasm32"))]
    impl RemoteBridge {
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
            &self,
            options: ListenOptions,
            channel: mpsc::Sender<ChangeNotification>,
        ) -> WebSocketHandle {
            let handle = self.client.listen(options, move |notification| {
                let tx = channel.clone();
                async move {
                    tracing::debug!(notification = ?notification);
                    let _ = tx.send(notification).await;
                }
            });

            handle
        }
    }
}
