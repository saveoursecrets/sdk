//! Handler that can synchronize account data between a
//! remote data source and local account.
use crate::{
    AsConflict, ConflictError, MaybeDiff, Merge, MergeOutcome, Origin,
    SyncClient, SyncDirection, SyncPacket, SyncStatus, SyncStorage,
};
use async_trait::async_trait;
use sos_sdk::prelude::{Account, Address};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[cfg(feature = "files")]
use crate::transfer::{
    FileOperation, FileTransferQueueSender, TransferOperation,
};

use super::ForceMerge;

/// Trait for types that bridge between a remote data source
/// and a local account.
#[async_trait]
pub trait RemoteSyncHandler {
    /// Client used to fetch data from the data source.
    type Client: SyncClient + Send + Sync + 'static;

    /// Local account.
    type Account: Account
        + SyncStorage
        + Merge
        + ForceMerge
        + Send
        + Sync
        + 'static;

    /// Error implementation.
    type Error: std::error::Error
        + std::fmt::Debug
        + AsConflict
        + From<ConflictError>
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + From<<Self::Account as Account>::Error>
        + From<<Self::Client as SyncClient>::Error>
        + Send
        + Sync
        + 'static;

    /// Client implementation.
    fn client(&self) -> &Self::Client;

    /// Remote origin.
    fn origin(&self) -> &Origin;

    /// Account address.
    fn address(&self) -> &Address;

    /// Local account.
    fn account(&self) -> Arc<Mutex<Self::Account>>;

    /// Direction for account creation and auto merge.
    fn direction(&self) -> SyncDirection;

    /// Queue for file transfers.
    #[cfg(feature = "files")]
    fn file_transfer_queue(&self) -> &FileTransferQueueSender;

    /// Sync file transfers.
    #[cfg(feature = "files")]
    async fn execute_sync_file_transfers(&self) -> Result<(), Self::Error>;

    /// Push an account to the remote.
    #[doc(hidden)]
    async fn create_push_account(&self) -> Result<(), Self::Error> {
        {
            let account = self.account();
            let account = account.lock().await;
            let public_account = account.change_set().await?;
            self.client()
                .create_account(self.address(), public_account)
                .await?;
        }

        #[cfg(feature = "files")]
        self.execute_sync_file_transfers().await?;

        Ok(())
    }

    /// Pull an account from the remote.
    #[doc(hidden)]
    async fn create_pull_account(&self) -> Result<(), Self::Error> {
        // Get account data from the remote.
        let public_account =
            self.client().fetch_account(self.address()).await?;

        {
            let account = self.account();
            let mut account = account.lock().await;
            account
                .import_account_events(
                    public_account.identity,
                    public_account.account,
                    public_account.device,
                    public_account.folders,
                    #[cfg(feature = "files")]
                    public_account.files,
                )
                .await?;
        }

        /*
        #[cfg(feature = "files")]
        self.execute_sync_file_transfers().await?;
        */

        Ok(())
    }

    /// Create an account on local or remote depending
    /// on the sync direction.
    async fn create_account(&self) -> Result<(), Self::Error> {
        match self.direction() {
            SyncDirection::Push => self.create_push_account().await,
            SyncDirection::Pull => self.create_pull_account().await,
        }
    }

    /// Sync the account.
    async fn sync_account(
        &self,
        remote_status: SyncStatus,
    ) -> Result<MergeOutcome, Self::Error> {
        let account = self.account();
        let mut account = account.lock().await;

        tracing::debug!("merge_client");

        let (needs_sync, local_status, local_changes) =
            crate::diff(&*account, remote_status).await?;

        tracing::debug!(needs_sync = %needs_sync, "merge_client");

        let mut outcome = MergeOutcome::default();

        if needs_sync {
            let packet = SyncPacket {
                status: local_status,
                diff: local_changes,
                compare: None,
            };
            let remote_changes =
                self.client().sync(self.address(), packet.clone()).await?;

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
                    use sos_sdk::account::Account;
                    let paths = account.paths();
                    // let mut writer = self.transfers.write().await;

                    for file in outcome.external_files.drain(..) {
                        let file_path = paths.file_location(
                            file.vault_id(),
                            file.secret_id(),
                            file.file_name().to_string(),
                        );
                        if !sos_sdk::vfs::try_exists(file_path).await? {
                            tracing::debug!(
                                file = ?file,
                                "add file download to transfers",
                            );

                            if self.file_transfer_queue().receiver_count() > 0
                            {
                                let _ =
                                    self.file_transfer_queue().send(vec![
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
                return Err(ConflictError::Soft {
                    conflict: maybe_conflict,
                    local: packet.status,
                    remote: remote_changes.status,
                }
                .into());
            }
        }

        Ok(outcome)
    }
}
