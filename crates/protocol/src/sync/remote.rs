//! Handler that can synchronize account data between a
//! remote data source and local account.
use crate::{
    MaybeDiff, Merge, MergeOutcome, Origin, RemoteResult, RemoteSync,
    SyncClient, SyncOptions, SyncPacket, SyncStatus, SyncStorage, UpdateSet,
};
use async_trait::async_trait;
use sos_sdk::prelude::{Account, Address};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

/*
#[cfg(feature = "files")]
use crate::{
    account::file_transfers::FileTransferQueueRequest,
    protocol::{FileOperation, FileSet, FileSyncClient, TransferOperation},
};
*/

/// Trait for types that bridge between a remote data source
/// and a local account.
#[async_trait]
pub trait RemoteSyncHandler {
    /// Client used to fetch data from the data source.
    type Client: SyncClient;

    /// Local account.
    type Account: Account + SyncStorage + Merge + Send + Sync + 'static;

    /// Error implementation.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + From<<Self::Client as SyncClient>::Error>;

    /// Client implementation.
    fn client(&self) -> &Self::Client;

    /// Remote origin.
    fn origin(&self) -> &Origin;

    /// Account address.
    fn address(&self) -> &Address;

    /// Local account.
    fn account(&self) -> Arc<Mutex<Self::Account>>;

    /// Create an account on the remote.
    async fn create_remote_account(&self) -> Result<(), Self::Error> {
        {
            let account = self.account();
            let account = account.lock().await;
            let public_account = account.change_set().await?;
            self.client()
                .create_account(self.address(), public_account)
                .await?;
        }

        /*
        #[cfg(feature = "files")]
        self.execute_sync_file_transfers().await?;
        */

        Ok(())
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
            let remote_changes = self.client().sync(packet.clone()).await?;

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

                            /*
                            if self.file_transfer_queue.receiver_count() > 0 {
                                let _ = self.file_transfer_queue.send(vec![
                                    FileOperation(
                                        file,
                                        TransferOperation::Download,
                                    ),
                                ]);
                            }
                            */
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

                /*
                return Err(Error::SoftConflict {
                    conflict: maybe_conflict,
                    local: packet.status,
                    remote: remote_changes.status,
                });
                */

                todo!();
            }
        }

        Ok(outcome)
    }

    /// Execute the sync operation.
    ///
    /// If the account does not exist it is created
    /// on the remote, otherwise the account is synced.
    async fn execute_sync(
        &self,
        options: &SyncOptions,
    ) -> Result<Option<MergeOutcome>, Self::Error> {
        let exists = self.client().account_exists(self.address()).await?;
        if exists {
            let sync_status = self.client().sync_status().await?;

            /*
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
            */

            todo!();
        } else {
            self.create_remote_account().await?;
            Ok(None)
        }
    }

    /*
    #[cfg(feature = "files")]
    async fn execute_sync_file_transfers(&self) -> Result<(), Self::Error> {
        use sos_sdk::storage::StorageEventLogs;
        let external_files = {
            let account = self.account();
            let account = account.lock().await;
            account.canonical_files().await?
        };

        let file_set = FileSet(external_files);
        let file_transfers = self.client().compare_files(file_set).await?;

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
    */
}

/*
#[async_trait]
impl<T> RemoteSync for T
where
    T: RemoteSyncHandler + Send + Sync + 'static,
{
    type Error = crate::Error;

    async fn sync(&self) -> RemoteResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error> {
        match self.execute_sync(options).await {
            Ok(outcome) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(outcome),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error> {
        match self.execute_sync_file_transfers().await {
            Ok(_) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        match self
            .client()
            .update_account(self.address(), account_data)
            .await
        {
            Ok(_) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }
}
*/
