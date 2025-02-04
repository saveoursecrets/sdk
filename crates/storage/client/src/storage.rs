use crate::{
    files::ExternalFileManager, filesystem::ClientFileSystemStorage,
    ClientAccountStorage, ClientDeviceStorage, ClientFolderStorage,
    ClientSecretStorage, Error, Result, StorageChangeEvent,
};
use crate::{AccessOptions, AccountPack, NewFolderOptions};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, Folder, FolderEventLog,
};
use sos_core::{
    commit::{CommitHash, CommitState},
    SecretId, VaultId,
};
use sos_core::{
    crypto::AccessKey,
    device::{DevicePublicKey, TrustedDevice},
    events::{
        patch::FolderPatch, AccountEvent, DeviceEvent, Event, EventRecord,
        ReadEvent, WriteEvent,
    },
    AccountId, Paths, UtcDateTime,
};
use sos_database::async_sqlite::Client;
use sos_login::{FolderKeys, Identity};
use sos_sync::StorageEventLogs;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    FolderRef, Summary, Vault, VaultCommit, VaultFlags,
};
use std::{borrow::Cow, collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

#[cfg(feature = "files")]
use sos_backend::FileEventLog;

/// Client account storage.
pub enum ClientStorage {
    /// Filesystem storage.
    FileSystem(ClientFileSystemStorage),
    /// Database storage.
    Database(ClientFileSystemStorage), // TODO!: db storage
}

impl ClientStorage {
    /// Create new client storage.
    pub async fn new_unauthenticated(
        account_id: AccountId,
        target: BackendTarget,
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Ok(Self::new_unauthenticated_fs(account_id, paths).await?)
            }
            BackendTarget::Database(client) => {
                Ok(Self::new_unauthenticated_db(account_id, client).await?)
            }
        }
    }

    /// Create new client storage in authenticated state.
    pub async fn new_authenticated(
        account_id: AccountId,
        target: BackendTarget,
        authenticated_user: Identity,
        /*
        identity_log: Arc<RwLock<FolderEventLog>>,
        device: TrustedDevice,
        */
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Ok(Self::new_authenticated_fs(
                    account_id,
                    paths,
                    authenticated_user,
                    /*
                    identity_log,
                    device,
                    */
                )
                .await?)
            }
            BackendTarget::Database(client) => {
                Ok(Self::new_authenticated_db(
                    account_id,
                    client,
                    authenticated_user,
                    // identity_log,
                    // device,
                )
                .await?)
            }
        }
    }

    /// Create new file system storage.
    async fn new_unauthenticated_fs(
        account_id: AccountId,
        paths: Paths,
    ) -> Result<Self> {
        Ok(Self::FileSystem(
            ClientFileSystemStorage::new_unauthenticated(account_id, paths)
                .await?,
        ))
    }

    /// Create new file system storage in authenticated state.
    async fn new_authenticated_fs(
        account_id: AccountId,
        paths: Paths,
        authenticated_user: Identity,
        /*
        identity_log: Arc<RwLock<FolderEventLog>>,
        device: TrustedDevice,
        */
    ) -> Result<Self> {
        Ok(Self::FileSystem(
            ClientFileSystemStorage::new_authenticated(
                account_id,
                paths,
                authenticated_user,
                /*
                identity_log,
                device,
                */
            )
            .await?,
        ))
    }

    /// Create new file system storage.
    async fn new_unauthenticated_db(
        account_id: AccountId,
        client: Client,
    ) -> Result<Self> {
        /*
        Ok(Self::FileSystem(
            ClientFileSystemStorage::new_unauthenticated(account_id, paths).await?,
        ))
        */

        todo!("unauthenticated db storage");
    }

    /// Create new file system storage in authenticated state.
    async fn new_authenticated_db(
        account_id: AccountId,
        client: Client,
        authenticated_user: Identity,
        /*
        identity_log: Arc<RwLock<FolderEventLog>>,
        device: TrustedDevice,
        */
    ) -> Result<Self> {
        /*
        Ok(Self::FileSystem(
            ClientFileSystemStorage::new_authenticated(
                account_id,
                paths,
                identity_log,
                device,
            )
            .await?,
        ))
        */

        todo!("authenticated db storage");
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientSecretStorage for ClientStorage {
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.create_secret(secret_data, options).await
            }
            ClientStorage::Database(db) => {
                db.create_secret(secret_data, options).await
            }
        }
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'_, VaultCommit>, ReadEvent)>> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.raw_secret(folder_id, secret_id).await
            }
            ClientStorage::Database(db) => {
                db.raw_secret(folder_id, secret_id).await
            }
        }
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_secret(id).await,
            ClientStorage::Database(db) => db.read_secret(id).await,
        }
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.update_secret(secret_id, meta, secret, options).await
            }
            ClientStorage::Database(db) => {
                db.update_secret(secret_id, meta, secret, options).await
            }
        }
    }

    async fn write_secret(
        &mut self,
        id: &SecretId,
        secret_data: SecretRow,
        is_update: bool,
    ) -> Result<WriteEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.write_secret(id, secret_data, is_update).await
            }
            ClientStorage::Database(db) => {
                db.write_secret(id, secret_data, is_update).await
            }
        }
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.delete_secret(secret_id, options).await
            }
            ClientStorage::Database(db) => {
                db.delete_secret(secret_id, options).await
            }
        }
    }

    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent> {
        match self {
            ClientStorage::FileSystem(fs) => fs.remove_secret(id).await,
            ClientStorage::Database(db) => db.remove_secret(id).await,
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

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.create_folder(name, options).await
            }
            ClientStorage::Database(db) => {
                db.create_folder(name, options).await
            }
        }
    }

    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.import_folder(buffer, key, apply_event, creation_time)
                    .await
            }
            ClientStorage::Database(db) => {
                db.import_folder(buffer, key, apply_event, creation_time)
                    .await
            }
        }
    }

    async fn load_folders(&mut self) -> Result<&[Summary]> {
        match self {
            ClientStorage::FileSystem(fs) => fs.load_folders().await,
            ClientStorage::Database(db) => db.load_folders().await,
        }
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.delete_folder(summary, apply_event).await
            }
            ClientStorage::Database(db) => {
                db.delete_folder(summary, apply_event).await
            }
        }
    }

    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.remove_folder(folder_id).await
            }
            ClientStorage::Database(db) => db.remove_folder(folder_id).await,
        }
    }

    fn list_folders(&self) -> &[Summary] {
        match self {
            ClientStorage::FileSystem(fs) => fs.list_folders(),
            ClientStorage::Database(db) => db.list_folders(),
        }
    }

    fn current_folder(&self) -> Option<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.current_folder(),
            ClientStorage::Database(db) => db.current_folder(),
        }
    }

    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        match self {
            ClientStorage::FileSystem(fs) => fs.find_folder(vault),
            ClientStorage::Database(db) => db.find_folder(vault),
        }
    }

    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        match self {
            ClientStorage::FileSystem(fs) => fs.find(predicate),
            ClientStorage::Database(db) => db.find(predicate),
        }
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent> {
        match self {
            ClientStorage::FileSystem(fs) => fs.open_folder(summary).await,
            ClientStorage::Database(db) => db.open_folder(summary).await,
        }
    }

    fn close_folder(&mut self) {
        match self {
            ClientStorage::FileSystem(fs) => fs.close_folder(),
            ClientStorage::Database(db) => db.close_folder(),
        }
    }

    async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.import_folder_patches(patches).await
            }
            ClientStorage::Database(db) => {
                db.import_folder_patches(patches).await
            }
        }
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.compact_folder(summary, key).await
            }
            ClientStorage::Database(db) => {
                db.compact_folder(summary, key).await
            }
        }
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.restore_folder(folder_id, records, key).await
            }
            ClientStorage::Database(db) => {
                db.restore_folder(folder_id, records, key).await
            }
        }
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.rename_folder(summary, name).await
            }
            ClientStorage::Database(db) => {
                db.rename_folder(summary, name).await
            }
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

    fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_folder_name(summary, name)
            }
            ClientStorage::Database(db) => db.set_folder_name(summary, name),
        }
    }

    fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_folder_flags(summary, flags)
            }
            ClientStorage::Database(db) => {
                db.set_folder_flags(summary, flags)
            }
        }
    }

    async fn description(&self) -> Result<String> {
        match self {
            ClientStorage::FileSystem(fs) => fs.description().await,
            ClientStorage::Database(db) => db.description().await,
        }
    }

    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_description(description).await
            }
            ClientStorage::Database(db) => {
                db.set_description(description).await
            }
        }
    }

    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.change_password(vault, current_key, new_key).await
            }
            ClientStorage::Database(db) => {
                db.change_password(vault, current_key, new_key).await
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
    fn account_id(&self) -> &AccountId {
        match self {
            ClientStorage::FileSystem(fs) => fs.account_id(),
            ClientStorage::Database(db) => db.account_id(),
        }
    }

    async fn is_authenticated(&self) -> bool {
        match self {
            ClientStorage::FileSystem(fs) => fs.is_authenticated().await,
            ClientStorage::Database(db) => db.is_authenticated().await,
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

    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.create_account(account).await,
            ClientStorage::Database(db) => db.create_account(account).await,
        }
    }

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        match self {
            ClientStorage::FileSystem(fs) => fs.read_vault(id).await,
            ClientStorage::Database(db) => db.read_vault(id).await,
        }
    }

    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        match self {
            ClientStorage::FileSystem(fs) => fs.history(summary).await,
            ClientStorage::Database(db) => db.history(summary).await,
        }
    }

    async fn identity_state(&self) -> Result<CommitState> {
        match self {
            ClientStorage::FileSystem(fs) => fs.identity_state().await,
            ClientStorage::Database(db) => db.identity_state().await,
        }
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        match self {
            ClientStorage::FileSystem(fs) => fs.commit_state(summary).await,
            ClientStorage::Database(db) => db.commit_state(summary).await,
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
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    ) {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.set_file_password(file_password)
            }
            ClientStorage::Database(db) => {
                db.set_file_password(file_password)
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
    fn index(&self) -> Result<&AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.index(),
            ClientStorage::Database(db) => db.index(),
        }
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        match self {
            ClientStorage::FileSystem(fs) => fs.index_mut(),
            ClientStorage::Database(db) => db.index_mut(),
        }
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.initialize_search_index(keys).await
            }
            ClientStorage::Database(db) => {
                db.initialize_search_index(keys).await
            }
        }
    }

    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        match self {
            ClientStorage::FileSystem(fs) => {
                fs.build_search_index(keys).await
            }
            ClientStorage::Database(db) => db.build_search_index(keys).await,
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
