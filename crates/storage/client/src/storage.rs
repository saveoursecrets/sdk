use crate::{
    database::ClientDatabaseStorage,
    files::ExternalFileManager,
    filesystem::ClientFileSystemStorage,
    traits::{
        private::Internal, ClientAccountStorage, ClientBaseStorage,
        ClientDeviceStorage, ClientFolderStorage, ClientVaultStorage,
    },
    AccountPack, Error, NewFolderOptions, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, Folder, FolderEventLog,
};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    device::{DevicePublicKey, TrustedDevice},
    events::{
        patch::{
            AccountDiff, CheckedPatch, DeviceDiff, FolderDiff, FolderPatch,
        },
        AccountEvent, DeviceEvent, Event, EventRecord, ReadEvent, WriteEvent,
    },
    AccountId, FolderRef, Paths, UtcDateTime, VaultId,
};
use sos_database::async_sqlite::Client;
use sos_login::{FolderKeys, Identity};
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
};
use sos_vault::{Summary, Vault, VaultFlags};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::patch::FileDiff};

use crate::sync::SyncImpl;

/// Client account storage.
pub enum ClientStorage {
    /// Filesystem storage.
    FileSystem(SyncImpl<ClientFileSystemStorage>),
    /// Database storage.
    Database(SyncImpl<ClientDatabaseStorage>),
}

impl ClientStorage {
    /// Create new client storage.
    pub async fn new_unauthenticated(
        paths: &Paths,
        account_id: &AccountId,
        target: BackendTarget,
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Ok(Self::new_unauthenticated_fs(paths, account_id).await?)
            }
            BackendTarget::Database(client) => {
                Ok(Self::new_unauthenticated_db(paths, account_id, client)
                    .await?)
            }
        }
    }

    /// Create new file system storage.
    async fn new_unauthenticated_fs(
        paths: Paths,
        account_id: &AccountId,
    ) -> Result<Self> {
        debug_assert!(!paths.is_server());

        Ok(Self::FileSystem(SyncImpl::new(
            ClientFileSystemStorage::new_unauthenticated(paths, account_id)
                .await?,
        )))
    }

    /// Create new database storage.
    async fn new_unauthenticated_db(
        paths: &Paths,
        account_id: &AccountId,
        client: Client,
    ) -> Result<Self> {
        debug_assert!(!paths.is_server());

        Ok(Self::Database(SyncImpl::new(
            ClientDatabaseStorage::new_unauthenticated(
                paths, account_id, client,
            )
            .await?,
        )))
    }
}

impl ClientBaseStorage for ClientStorage {
    fn account_id(&self) -> &AccountId {
        match self {
            ClientStorage::FileSystem(fs) => fs.account_id(),
            ClientStorage::Database(db) => db.account_id(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientVaultStorage for ClientStorage {
    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_vault(id).await,
            ClientStorage::Database(db) => db.read_vault(id).await,
        }
    }

    async fn write_vault(&self, vault: &Vault) -> Result<Vec<u8>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.write_vault(vault).await,
            ClientStorage::Database(db) => db.write_vault(vault).await,
        }
    }

    async fn remove_vault(&self, id: &VaultId) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.remove_vault(id).await,
            ClientStorage::Database(db) => db.remove_vault(id).await,
        }
    }

    async fn read_folders(&self) -> Result<Vec<Summary>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_folders().await,
            ClientStorage::Database(db) => db.read_folders().await,
        }
    }

    fn summaries(&self, token: Internal) -> &Vec<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.summaries(token),
            ClientStorage::Database(db) => db.summaries(token),
        }
    }

    fn summaries_mut(&mut self, token: Internal) -> &mut Vec<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.summaries_mut(token),
            ClientStorage::Database(db) => db.summaries_mut(token),
        }
    }

    fn current_folder(&self) -> Option<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.current_folder(),
            ClientStorage::Database(db) => db.current_folder(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientFolderStorage for ClientStorage {
    fn folders(&self) -> &HashMap<VaultId, Folder> {
        match self {
            ClientStorage::FileSystem(fs) => fs.folders(),
            ClientStorage::Database(db) => db.folders(),
        }
    }

    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder> {
        match self {
            ClientStorage::FileSystem(fs) => fs.folders_mut(),
            ClientStorage::Database(db) => db.folders_mut(),
        }
    }

    async fn new_folder(&self, folder_id: &VaultId) -> Result<Folder> {
        match self {
            ClientStorage::FileSystem(fs) => fs.new_folder(folder_id).await,
            ClientStorage::Database(db) => db.new_folder(folder_id).await,
        }
    }

    fn open_folder(&self, folder_id: &VaultId) -> Result<ReadEvent> {
        match self {
            ClientStorage::FileSystem(fs) => fs.open_folder(folder_id),
            ClientStorage::Database(db) => db.open_folder(folder_id),
        }
    }

    fn close_folder(&self) {
        match self {
            ClientStorage::FileSystem(fs) => fs.close_folder(),
            ClientStorage::Database(db) => db.close_folder(),
        }
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.update_folder_flags(summary, flags).await
            }
            ClientStorage::Database(db) => {
                db.update_folder_flags(summary, flags).await
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientStorage {
    fn devices(&self) -> &IndexSet<TrustedDevice> {
        match self {
            ClientStorage::FileSystem(fs) => fs.devices(),
            ClientStorage::Database(db) => db.devices(),
        }
    }

    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>) {
        match self {
            ClientStorage::FileSystem(fs) => fs.set_devices(devices),
            ClientStorage::Database(db) => db.set_devices(devices),
        }
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        match self {
            ClientStorage::FileSystem(fs) => fs.list_trusted_devices(),
            ClientStorage::Database(db) => db.list_trusted_devices(),
        }
    }

    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.patch_devices_unchecked(events).await
            }
            ClientStorage::Database(db) => {
                db.patch_devices_unchecked(events).await
            }
        }
    }

    async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.revoke_device(public_key).await
            }
            ClientStorage::Database(db) => db.revoke_device(public_key).await,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientAccountStorage for ClientStorage {
    fn authenticated_user(&self) -> Option<&Identity> {
        match self {
            ClientStorage::FileSystem(fs) => fs.authenticated_user(),
            ClientStorage::Database(db) => db.authenticated_user(),
        }
    }

    fn authenticated_user_mut(&mut self) -> Option<&mut Identity> {
        match self {
            ClientStorage::FileSystem(fs) => fs.authenticated_user_mut(),
            ClientStorage::Database(db) => db.authenticated_user_mut(),
        }
    }

    fn is_authenticated(&self) -> bool {
        match self {
            ClientStorage::FileSystem(fs) => fs.is_authenticated(),
            ClientStorage::Database(db) => db.is_authenticated(),
        }
    }

    fn drop_authenticated_state(&mut self, private: Internal) {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.drop_authenticated_state(private)
            }
            ClientStorage::Database(db) => {
                db.drop_authenticated_state(private)
            }
        }
    }

    async fn authenticate(
        &mut self,
        authenticated_user: Identity,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.authenticate(authenticated_user).await
            }
            ClientStorage::Database(db) => {
                db.authenticate(authenticated_user).await
            }
        }
    }

    async fn sign_out(&mut self) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.sign_out().await,
            ClientStorage::Database(db) => db.sign_out().await,
        }
    }

    async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.import_identity_vault(vault).await
            }
            ClientStorage::Database(db) => {
                db.import_identity_vault(vault).await
            }
        }
    }

    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.unlock(keys).await,
            ClientStorage::Database(db) => db.unlock(keys).await,
        }
    }

    async fn lock(&mut self) {
        match self {
            ClientStorage::FileSystem(fs) => fs.lock().await,
            ClientStorage::Database(db) => db.lock().await,
        }
    }

    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.unlock_folder(id, key).await,
            ClientStorage::Database(db) => db.unlock_folder(id, key).await,
        }
    }

    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.lock_folder(id).await,
            ClientStorage::Database(db) => db.lock_folder(id).await,
        }
    }

    fn paths(&self) -> Arc<Paths> {
        match self {
            ClientStorage::FileSystem(fs) => fs.paths(),
            ClientStorage::Database(db) => db.paths(),
        }
    }

    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.restore_archive(targets, folder_keys).await
            }
            ClientStorage::Database(db) => {
                db.restore_archive(targets, folder_keys).await
            }
        }
    }

    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> &ExternalFileManager {
        match self {
            ClientStorage::FileSystem(fs) => fs.external_file_manager(),
            ClientStorage::Database(db) => db.external_file_manager(),
        }
    }

    #[cfg(feature = "files")]
    fn external_file_manager_mut(&mut self) -> &mut ExternalFileManager {
        match self {
            ClientStorage::FileSystem(fs) => fs.external_file_manager_mut(),
            ClientStorage::Database(db) => db.external_file_manager_mut(),
        }
    }

    #[cfg(feature = "search")]
    fn index(&self) -> Option<&AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.index(),
            ClientStorage::Database(db) => db.index(),
        }
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Option<&mut AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.index_mut(),
            ClientStorage::Database(db) => db.index_mut(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.identity_log().await,
            ClientStorage::Database(db) => db.identity_log().await,
        }
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.account_log().await,
            ClientStorage::Database(db) => db.account_log().await,
        }
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.device_log().await,
            ClientStorage::Database(db) => db.device_log().await,
        }
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.file_log().await,
            ClientStorage::Database(db) => db.file_log().await,
        }
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.folder_details().await,
            ClientStorage::Database(db) => db.folder_details().await,
        }
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.folder_log(id).await,
            ClientStorage::Database(db) => db.folder_log(id).await,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ForceMerge for ClientStorage {
    async fn force_merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.force_merge_identity(diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.force_merge_identity(diff, outcome).await
            }
        }
    }

    /// Force merge changes to the files event log.
    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.force_merge_folder(folder_id, diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.force_merge_folder(folder_id, diff, outcome).await
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Merge for ClientStorage {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.merge_identity(diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.merge_identity(diff, outcome).await
            }
        }
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.merge_account(diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.merge_account(diff, outcome).await
            }
        }
    }

    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.merge_device(diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.merge_device(diff, outcome).await
            }
        }
    }

    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.merge_files(diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.merge_files(diff, outcome).await
            }
        }
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.merge_folder(folder_id, diff, outcome).await
            }
            ClientStorage::Database(db) => {
                db.merge_folder(folder_id, diff, outcome).await
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncStorage for ClientStorage {
    fn is_client_storage(&self) -> bool {
        true
    }
}
