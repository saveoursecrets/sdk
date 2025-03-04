use crate::{
    database::ServerDatabaseStorage, filesystem::ServerFileStorage, Error,
    Result, ServerAccountStorage,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, FolderEventLog,
};
use sos_core::{
    commit::{CommitState, Comparison},
    device::{DevicePublicKey, TrustedDevice},
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        EventLog, WriteEvent,
    },
    AccountId, Paths, VaultFlags, VaultId,
};
use sos_database::entity::AccountEntity;
use sos_sync::{
    CreateSet, ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStatus,
    SyncStorage,
};
use sos_vault::{Summary, Vault};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::patch::FileDiff};

use crate::sync::SyncImpl;

/// Server storage backed by filesystem or database.
pub enum ServerStorage {
    /// Filesystem storage.
    FileSystem(SyncImpl<ServerFileStorage>),
    /// Database storage.
    Database(SyncImpl<ServerDatabaseStorage>),
}

impl ServerStorage {
    /// Create new server storage.
    pub async fn new(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::new_fs(
                    BackendTarget::FileSystem(
                        paths.with_account_id(account_id),
                    ),
                    account_id,
                )
                .await
            }
            BackendTarget::Database(paths, client) => {
                Self::new_db(
                    BackendTarget::Database(paths, client),
                    account_id,
                )
                .await
            }
        }
    }

    /// Create new file system storage.
    async fn new_fs(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self> {
        debug_assert!(matches!(target, BackendTarget::FileSystem(_)));
        debug_assert!(target.paths().is_server());

        let target = target.with_account_id(account_id);
        let mut event_log =
            FolderEventLog::new_login_folder(target.clone(), account_id)
                .await?;
        event_log.load_tree().await?;

        Ok(Self::FileSystem(SyncImpl::new(
            ServerFileStorage::new(
                target,
                account_id,
                Arc::new(RwLock::new(event_log)),
            )
            .await?,
        )))
    }

    /// Create an account in server storage.
    pub async fn create_account(
        target: BackendTarget,
        account_id: &AccountId,
        account_data: &CreateSet,
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::create_fs_account(
                    BackendTarget::FileSystem(paths),
                    account_id,
                    account_data,
                )
                .await
            }
            BackendTarget::Database(paths, client) => {
                Self::create_db_account(
                    BackendTarget::Database(paths, client),
                    account_id,
                    account_data,
                )
                .await
            }
        }
    }

    /// Create a new file system account.
    async fn create_fs_account(
        target: BackendTarget,
        account_id: &AccountId,
        account_data: &CreateSet,
    ) -> Result<Self> {
        debug_assert!(matches!(target, BackendTarget::FileSystem(_)));
        let BackendTarget::FileSystem(paths) = &target else {
            panic!("filesystem backend expected");
        };
        debug_assert!(paths.is_server());

        let paths = paths.with_account_id(account_id);
        paths.ensure().await?;

        let identity_log = ServerFileStorage::initialize_account(
            &target,
            account_id,
            &paths,
            &account_data.identity,
        )
        .await?;

        let target = target.with_account_id(account_id);
        let mut storage = ServerFileStorage::new(
            target,
            account_id,
            Arc::new(RwLock::new(identity_log)),
        )
        .await?;
        storage.import_account(&account_data).await?;

        Ok(Self::FileSystem(SyncImpl::new(storage)))
    }

    /// Create new database storage.
    async fn new_db(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self> {
        debug_assert!(matches!(target, BackendTarget::Database(_, _)));
        let BackendTarget::Database(paths, client) = &target else {
            panic!("database backend expected");
        };
        debug_assert!(paths.is_server());

        let (_, login_folder) =
            AccountEntity::find_account_with_login(&client, account_id)
                .await?;

        let mut event_log = FolderEventLog::new_folder(
            target.clone(),
            account_id,
            login_folder.summary.id(),
        )
        .await?;
        event_log.load_tree().await?;

        let target = target.with_account_id(account_id);
        Ok(Self::Database(SyncImpl::new(
            ServerDatabaseStorage::new(
                target,
                account_id,
                Arc::new(RwLock::new(event_log)),
            )
            .await?,
        )))
    }

    /// Create a new database account.
    async fn create_db_account(
        target: BackendTarget,
        account_id: &AccountId,
        account_data: &CreateSet,
    ) -> Result<Self> {
        let BackendTarget::Database(paths, _) = &target else {
            panic!("database backend expected");
        };
        debug_assert!(paths.is_server());

        let identity_log = ServerDatabaseStorage::initialize_account(
            &target,
            account_id,
            &account_data.identity,
        )
        .await?;

        let target = target.with_account_id(account_id);
        let mut storage = ServerDatabaseStorage::new(
            target,
            account_id,
            Arc::new(RwLock::new(identity_log)),
        )
        .await?;
        storage.import_account(&account_data).await?;

        Ok(Self::Database(SyncImpl::new(storage)))
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

    fn folders(&self) -> &HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.folders(),
            ServerStorage::Database(db) => db.folders(),
        }
    }

    fn folders_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.folders_mut(),
            ServerStorage::Database(db) => db.folders_mut(),
        }
    }

    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>) {
        match self {
            ServerStorage::FileSystem(fs) => fs.set_devices(devices),
            ServerStorage::Database(db) => db.set_devices(devices),
        }
    }

    async fn rename_account(&self, name: &str) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.rename_account(name).await,
            ServerStorage::Database(db) => db.rename_account(name).await,
        }
    }

    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault> {
        match self {
            ServerStorage::FileSystem(fs) => fs.read_vault(folder_id).await,
            ServerStorage::Database(db) => db.read_vault(folder_id).await,
        }
    }

    async fn write_vault(&self, vault: &Vault) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.write_vault(vault).await,
            ServerStorage::Database(db) => db.write_vault(vault).await,
        }
    }

    /*
    async fn read_login_vault(&self) -> Result<Vault> {
        match self {
            ServerStorage::FileSystem(fs) => fs.read_login_vault().await,
            ServerStorage::Database(db) => db.read_login_vault().await,
        }
    }
    */

    async fn write_login_vault(&self, vault: &Vault) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.write_login_vault(vault).await
            }
            ServerStorage::Database(db) => db.write_login_vault(vault).await,
        }
    }

    async fn replace_folder(
        &self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<(FolderEventLog, Vault)> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.replace_folder(folder_id, diff).await
            }
            ServerStorage::Database(db) => {
                db.replace_folder(folder_id, diff).await
            }
        }
    }

    async fn set_folder_flags(
        &self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => {
                fs.set_folder_flags(folder_id, flags).await
            }
            ServerStorage::Database(db) => {
                db.set_folder_flags(folder_id, flags).await
            }
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

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_folder(id).await,
            ServerStorage::Database(db) => db.delete_folder(id).await,
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

    #[cfg(feature = "files")]
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

    #[cfg(feature = "files")]
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

    #[cfg(feature = "files")]
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

    #[cfg(feature = "files")]
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
