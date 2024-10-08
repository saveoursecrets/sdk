//! Bridge between local storage and a remote server.
use crate::{
    net::HttpClient,
    protocol::{
        MaybeDiff, Merge, MergeOutcome, Origin, SyncOptions, SyncPacket,
        SyncStatus, SyncStorage, UpdateSet,
    },
    sdk::{
        account::{Account, LocalAccount},
        signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
        storage::StorageEventLogs,
        vfs,
    },
    Error, RemoteResult, RemoteSync, Result, SyncClient,
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, Mutex};

#[cfg(feature = "files")]
use crate::{
    account::file_transfers::FileTransferQueueRequest,
    protocol::{FileOperation, FileSet, TransferOperation},
};

/// Collection of remote targets for synchronization.
pub(crate) type Remotes = HashMap<Origin, RemoteBridge>;

/// Bridge between a local account and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Origin for this remote.
    origin: Origin,
    /// Account so we can replay events
    /// when a remote diff is merged.
    pub(super) account: Arc<Mutex<LocalAccount>>,
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

        #[cfg(feature = "files")]
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

    /// Create an account on the remote.
    async fn create_remote_account(&self) -> Result<()> {
        {
            let account = self.account.lock().await;
            let public_account = account.change_set().await?;
            self.client.create_account(public_account).await?;
        }

        #[cfg(feature = "files")]
        self.execute_sync_file_transfers().await?;
        Ok(())
    }

    async fn sync_account(
        &self,
        remote_status: SyncStatus,
    ) -> Result<MergeOutcome> {
        let mut account = self.account.lock().await;

        tracing::debug!("merge_client");

        let (needs_sync, local_status, local_changes) =
            sos_protocol::diff(&*account, remote_status).await?;

        tracing::debug!(needs_sync = %needs_sync, "merge_client");

        let mut outcome = MergeOutcome::default();

        if needs_sync {
            let packet = SyncPacket {
                status: local_status,
                diff: local_changes,
                compare: None,
            };
            let remote_changes = self.client.sync(packet.clone()).await?;

            let maybe_conflict = remote_changes
                .compare
                .as_ref()
                .map(|c| c.maybe_conflict())
                .unwrap_or_default();
            let has_conflicts = maybe_conflict.has_conflicts();

            if !has_conflicts {
                account.merge(remote_changes.diff, &mut outcome).await?;

                // Compute which external files need to be downloaded
                // and add to the transfers queue

                #[cfg(feature = "files")]
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
                                let _ = self.file_transfer_queue.send(vec![
                                    FileOperation(
                                        file,
                                        TransferOperation::Download,
                                    ),
                                ]);
                            }
                        }
                    }
                }

                // self.compare(&mut *account, remote_changes).await?;
            } else {
                // Some parts of the remote patch may not
                // be in conflict and must still be merged
                if !maybe_conflict.identity {
                    if let Some(MaybeDiff::Diff(diff)) =
                        remote_changes.diff.identity
                    {
                        account.merge_identity(diff, &mut outcome).await?;
                    }
                }
                if !maybe_conflict.account {
                    if let Some(MaybeDiff::Diff(diff)) =
                        remote_changes.diff.account
                    {
                        account.merge_account(diff, &mut outcome).await?;
                    }
                }
                if !maybe_conflict.device {
                    if let Some(MaybeDiff::Diff(diff)) =
                        remote_changes.diff.device
                    {
                        account.merge_device(diff, &mut outcome).await?;
                    }
                }
                #[cfg(feature = "files")]
                if !maybe_conflict.files {
                    if let Some(MaybeDiff::Diff(diff)) =
                        remote_changes.diff.files
                    {
                        account.merge_files(diff, &mut outcome).await?;
                    }
                }

                let merge_folders = remote_changes
                    .diff
                    .folders
                    .into_iter()
                    .filter(|(k, _)| maybe_conflict.folders.get(k).is_none())
                    .collect::<HashMap<_, _>>();
                for (id, maybe_diff) in merge_folders {
                    if let MaybeDiff::Diff(diff) = maybe_diff {
                        account.merge_folder(&id, diff, &mut outcome).await?;
                    }
                }

                return Err(Error::SoftConflict {
                    conflict: maybe_conflict,
                    local: packet.status,
                    remote: remote_changes.status,
                });
            }
        }

        Ok(outcome)
    }

    async fn execute_sync(
        &self,
        options: &SyncOptions,
    ) -> Result<Option<MergeOutcome>> {
        let exists = self.client.account_exists().await?;
        if exists {
            let sync_status = self.client.sync_status().await?;
            match self.sync_account(sync_status).await {
                Ok(outcome) => Ok(Some(outcome)),
                Err(e) => match e {
                    Error::SoftConflict {
                        conflict,
                        local,
                        remote,
                    } => {
                        let outcome = self
                            .auto_merge(options, conflict, local, remote)
                            .await?;
                        Ok(Some(outcome))
                    }
                    _ => Err(e),
                },
            }
        } else {
            self.create_remote_account().await?;
            Ok(None)
        }
    }

    #[cfg(feature = "files")]
    async fn execute_sync_file_transfers(&self) -> Result<()> {
        let external_files = {
            let account = self.account.lock().await;
            account.canonical_files().await?
        };

        let file_set = FileSet(external_files);
        let file_transfers = self.client.compare_files(file_set).await?;

        let mut ops = Vec::new();
        for file in file_transfers.uploads.0 {
            ops.push(FileOperation(file, TransferOperation::Upload));
        }

        for file in file_transfers.downloads.0 {
            ops.push(FileOperation(file, TransferOperation::Download));
        }

        if !ops.is_empty() && self.file_transfer_queue.receiver_count() > 0 {
            let _ = self.file_transfer_queue.send(ops);
        }

        Ok(())
    }
}

#[async_trait]
impl RemoteSync for RemoteBridge {
    async fn sync(&self) -> RemoteResult {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(&self, options: &SyncOptions) -> RemoteResult {
        match self.execute_sync(options).await {
            Ok(outcome) => RemoteResult {
                origin: self.origin.clone(),
                result: Ok(outcome),
            },
            Err(e) => RemoteResult {
                origin: self.origin.clone(),
                result: Err(e),
            },
        }
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult {
        match self.execute_sync_file_transfers().await {
            Ok(_) => RemoteResult {
                origin: self.origin.clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin.clone(),
                result: Err(e),
            },
        }
    }

    async fn force_update(&self, account_data: UpdateSet) -> RemoteResult {
        match self.client.update_account(account_data).await {
            Ok(_) => RemoteResult {
                origin: self.origin.clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin.clone(),
                result: Err(e),
            },
        }
    }
}

#[cfg(feature = "listen")]
mod listen {
    use crate::{
        protocol::ChangeNotification, ListenOptions, RemoteBridge,
        WebSocketHandle,
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
