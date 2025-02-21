use crate::{
    database::ClientDatabaseStorage,
    filesystem::ClientFileSystemStorage,
    traits::{
        private::Internal, ClientAccountStorage, ClientBaseStorage,
        ClientDeviceStorage, ClientFolderStorage, ClientVaultStorage,
    },
    ClientEventLogStorage, Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, Folder, FolderEventLog,
};
use sos_core::{
    device::TrustedDevice,
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        ReadEvent, WriteEvent,
    },
    AccountId, Paths, VaultId,
};
use sos_database::async_sqlite::Client;
use sos_login::Identity;
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
};
use sos_vault::{Summary, Vault};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "search")]
use sos_search::AccountSearch;

#[cfg(feature = "files")]
use {
    crate::files::ExternalFileManager, sos_backend::FileEventLog,
    sos_core::events::patch::FileDiff,
};

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
            BackendTarget::Database(_, client) => {
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
    async fn write_vault(
        &self,
        vault: &Vault,
        token: Internal,
    ) -> Result<Vec<u8>> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.write_vault(vault, token).await
            }
            ClientStorage::Database(db) => db.write_vault(vault, token).await,
        }
    }

    async fn write_login_vault(
        &self,
        vault: &Vault,
        token: Internal,
    ) -> Result<Vec<u8>> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.write_login_vault(vault, token).await
            }
            ClientStorage::Database(db) => {
                db.write_login_vault(vault, token).await
            }
        }
    }

    async fn remove_vault(
        &self,
        id: &VaultId,
        token: Internal,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => fs.remove_vault(id, token).await,
            ClientStorage::Database(db) => db.remove_vault(id, token).await,
        }
    }

    async fn read_vaults(&self, token: Internal) -> Result<Vec<Summary>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_vaults(token).await,
            ClientStorage::Database(db) => db.read_vaults(token).await,
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

    async fn new_folder(
        &self,
        vault: &Vault,
        token: Internal,
    ) -> Result<Folder> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.new_folder(vault, token).await
            }
            ClientStorage::Database(db) => db.new_folder(vault, token).await,
        }
    }

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_vault(id).await,
            ClientStorage::Database(db) => db.read_vault(id).await,
        }
    }

    async fn read_login_vault(&self) -> Result<Vault> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_login_vault().await,
            ClientStorage::Database(db) => db.read_login_vault().await,
        }
    }

    fn current_folder(&self) -> Option<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.current_folder(),
            ClientStorage::Database(db) => db.current_folder(),
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

    fn set_devices(
        &mut self,
        devices: IndexSet<TrustedDevice>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => fs.set_devices(devices, token),
            ClientStorage::Database(db) => db.set_devices(devices, token),
        }
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        match self {
            ClientStorage::FileSystem(fs) => fs.list_trusted_devices(),
            ClientStorage::Database(db) => db.list_trusted_devices(),
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

    fn set_authenticated_user(
        &mut self,
        user: Option<Identity>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_authenticated_user(user, token)
            }
            ClientStorage::Database(db) => {
                db.set_authenticated_user(user, token)
            }
        }
    }

    fn paths(&self) -> Arc<Paths> {
        match self {
            ClientStorage::FileSystem(fs) => fs.paths(),
            ClientStorage::Database(db) => db.paths(),
        }
    }

    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> Option<&ExternalFileManager> {
        match self {
            ClientStorage::FileSystem(fs) => fs.external_file_manager(),
            ClientStorage::Database(db) => db.external_file_manager(),
        }
    }

    #[cfg(feature = "files")]
    fn external_file_manager_mut(
        &mut self,
    ) -> Option<&mut ExternalFileManager> {
        match self {
            ClientStorage::FileSystem(fs) => fs.external_file_manager_mut(),
            ClientStorage::Database(db) => db.external_file_manager_mut(),
        }
    }

    #[cfg(feature = "files")]
    fn set_external_file_manager(
        &mut self,
        file_manager: Option<ExternalFileManager>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_external_file_manager(file_manager, token)
            }
            ClientStorage::Database(db) => {
                db.set_external_file_manager(file_manager, token)
            }
        }
    }

    #[cfg(feature = "search")]
    fn search_index(&self) -> Option<&AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.search_index(),
            ClientStorage::Database(db) => db.search_index(),
        }
    }

    #[cfg(feature = "search")]
    fn search_index_mut(&mut self) -> Option<&mut AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.search_index_mut(),
            ClientStorage::Database(db) => db.search_index_mut(),
        }
    }

    #[cfg(feature = "search")]
    fn set_search_index(
        &mut self,
        index: Option<AccountSearch>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_search_index(index, token)
            }
            ClientStorage::Database(db) => db.set_search_index(index, token),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientEventLogStorage for ClientStorage {
    async fn initialize_device_log(
        &self,
        device: TrustedDevice,
        token: Internal,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.initialize_device_log(device, token).await
            }
            ClientStorage::Database(db) => {
                db.initialize_device_log(device, token).await
            }
        }
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(
        &self,
        token: Internal,
    ) -> Result<FileEventLog> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.initialize_file_log(token).await
            }
            ClientStorage::Database(db) => {
                db.initialize_file_log(token).await
            }
        }
    }

    fn set_identity_log(
        &mut self,
        log: Arc<RwLock<FolderEventLog>>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => fs.set_identity_log(log, token),
            ClientStorage::Database(db) => db.set_identity_log(log, token),
        }
    }

    fn set_device_log(
        &mut self,
        log: Arc<RwLock<DeviceEventLog>>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => fs.set_device_log(log, token),
            ClientStorage::Database(db) => db.set_device_log(log, token),
        }
    }

    #[cfg(feature = "files")]
    fn set_file_log(
        &mut self,
        log: Arc<RwLock<FileEventLog>>,
        token: Internal,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => fs.set_file_log(log, token),
            ClientStorage::Database(db) => db.set_file_log(log, token),
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
