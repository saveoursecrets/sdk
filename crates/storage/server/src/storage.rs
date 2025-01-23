use crate::{
    database::ServerDatabaseStorage, filesystem::ServerFileStorage, Error,
    Result, ServerAccountStorage,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, DeviceEventLog, FileEventLog, FolderEventLog,
};
use sos_core::{
    commit::{CommitState, Comparison},
    device::DevicePublicKey,
    events::{
        patch::{
            AccountDiff, CheckedPatch, DeviceDiff, FileDiff, FolderDiff,
        },
        EventLog, WriteEvent,
    },
    AccountId, Paths, VaultId,
};
use sos_sync::{
    CreateSet, ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStatus,
    SyncStorage, UpdateSet,
};
use sos_vault::Summary;
use std::{collections::HashSet, path::Path, sync::Arc};
use tokio::sync::RwLock;

/// Server storage backed by filesystem or database.
pub enum ServerStorage {
    /// Filesystem storage.
    FileSystem(ServerFileStorage),
    /// Database storage.
    Database(ServerDatabaseStorage),
}

impl ServerStorage {
    /// Create new file system storage.
    pub async fn new_fs(
        directory: impl AsRef<Path>,
        account_id: &AccountId,
    ) -> Result<Self> {
        let user_paths =
            Paths::new_server(directory.as_ref(), account_id.to_string());

        let mut event_log =
            FolderEventLog::new_fs_folder(user_paths.identity_events())
                .await?;
        event_log.load_tree().await?;
        let identity_log = Arc::new(RwLock::new(event_log));

        Ok(Self::FileSystem(
            ServerFileStorage::new(
                *account_id,
                Some(directory.as_ref().to_owned()),
                identity_log,
            )
            .await?,
        ))
    }

    /// Create a new file system account.
    pub async fn create_fs_account(
        directory: impl AsRef<Path>,
        account_id: &AccountId,
        account_data: &CreateSet,
    ) -> Result<Self> {
        let paths =
            Paths::new_server(directory.as_ref(), account_id.to_string());
        paths.ensure().await?;

        let identity_log = ServerFileStorage::initialize_account(
            &paths,
            &account_data.identity,
        )
        .await?;

        let mut storage = ServerFileStorage::new(
            *account_id,
            Some(directory.as_ref().to_owned()),
            Arc::new(RwLock::new(identity_log)),
        )
        .await?;
        storage.import_account(&account_data).await?;

        Ok(Self::FileSystem(storage))
    }
}

#[async_trait]
impl ServerAccountStorage for ServerStorage {
    fn account_id(&self) -> &AccountId {
        match self {
            ServerStorage::FileSystem(fs) => fs.account_id(),
            ServerStorage::Database(db) => db.account_id(),
        }
    }

    fn list_device_keys(&self) -> HashSet<&DevicePublicKey> {
        match self {
            ServerStorage::FileSystem(fs) => fs.list_device_keys(),
            ServerStorage::Database(db) => db.list_device_keys(),
        }
    }

    fn paths(&self) -> Arc<Paths> {
        match self {
            ServerStorage::FileSystem(fs) => fs.paths(),
            ServerStorage::Database(db) => db.paths(),
        }
    }

    async fn import_account(
        &mut self,
        account_data: &CreateSet,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.import_account(account_data).await
            }
            ServerStorage::Database(db) => {
                db.import_account(account_data).await
            }
        }
    }

    async fn update_account(
        &mut self,
        update_set: UpdateSet,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.update_account(update_set, outcome).await
            }
            ServerStorage::Database(db) => {
                db.update_account(update_set, outcome).await
            }
        }
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.load_folders().await,
            ServerStorage::Database(db) => db.load_folders().await,
        }
    }

    async fn import_folder(
        &mut self,
        id: &VaultId,
        buffer: &[u8],
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.import_folder(id, buffer).await
            }
            ServerStorage::Database(db) => db.import_folder(id, buffer).await,
        }
    }

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_folder(id).await,
            ServerStorage::Database(db) => db.delete_folder(id).await,
        }
    }

    async fn rename_folder(
        &mut self,
        id: &VaultId,
        name: &str,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.rename_folder(id, name).await,
            ServerStorage::Database(db) => db.rename_folder(id, name).await,
        }
    }

    async fn delete_account(&mut self) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_account().await,
            ServerStorage::Database(db) => db.delete_account().await,
        }
    }
}

#[async_trait]
impl Merge for ServerStorage {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.merge_identity(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.merge_identity(diff, outcome).await
            }
        }
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        match self {
            ServerStorage::FileSystem(fs) => fs.compare_identity(state).await,
            ServerStorage::Database(db) => db.compare_identity(state).await,
        }
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.merge_account(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.merge_account(diff, outcome).await
            }
        }
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        match self {
            ServerStorage::FileSystem(fs) => fs.compare_account(state).await,
            ServerStorage::Database(db) => db.compare_account(state).await,
        }
    }

    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.merge_device(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.merge_device(diff, outcome).await
            }
        }
    }

    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        match self {
            ServerStorage::FileSystem(fs) => fs.compare_device(state).await,
            ServerStorage::Database(db) => db.compare_device(state).await,
        }
    }

    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.merge_files(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.merge_files(diff, outcome).await
            }
        }
    }

    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        match self {
            ServerStorage::FileSystem(fs) => fs.compare_files(state).await,
            ServerStorage::Database(db) => db.compare_files(state).await,
        }
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.merge_folder(folder_id, diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.merge_folder(folder_id, diff, outcome).await
            }
        }
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.compare_folder(folder_id, state).await
            }
            ServerStorage::Database(db) => {
                db.compare_folder(folder_id, state).await
            }
        }
    }
}

#[async_trait]
impl ForceMerge for ServerStorage {
    async fn force_merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.force_merge_identity(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.force_merge_identity(diff, outcome).await
            }
        }
    }

    async fn force_merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.force_merge_account(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.force_merge_account(diff, outcome).await
            }
        }
    }

    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.force_merge_device(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.force_merge_device(diff, outcome).await
            }
        }
    }

    /// Force merge changes to the files event log.
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.force_merge_files(diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.force_merge_files(diff, outcome).await
            }
        }
    }

    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.force_merge_folder(folder_id, diff, outcome).await
            }
            ServerStorage::Database(db) => {
                db.force_merge_folder(folder_id, diff, outcome).await
            }
        }
    }
}

#[async_trait]
impl StorageEventLogs for ServerStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.identity_log().await,
            ServerStorage::Database(db) => db.identity_log().await,
        }
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.account_log().await,
            ServerStorage::Database(db) => db.account_log().await,
        }
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.device_log().await,
            ServerStorage::Database(db) => db.device_log().await,
        }
    }

    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.file_log().await,
            ServerStorage::Database(db) => db.file_log().await,
        }
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.folder_details().await,
            ServerStorage::Database(db) => db.folder_details().await,
        }
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.folder_log(id).await,
            ServerStorage::Database(db) => db.folder_log(id).await,
        }
    }
}

#[async_trait]
impl SyncStorage for ServerStorage {
    fn is_client_storage(&self) -> bool {
        false
    }

    async fn sync_status(&self) -> Result<SyncStatus> {
        match self {
            ServerStorage::FileSystem(fs) => fs.sync_status().await,
            ServerStorage::Database(db) => db.sync_status().await,
        }
    }
}
