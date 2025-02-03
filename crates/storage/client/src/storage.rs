use crate::{
    filesystem::ClientFileStorage, ClientAccountStorage, ClientDeviceStorage,
    ClientFolderStorage, ClientSecretStorage, Error, Result,
    StorageChangeEvent,
};
use crate::{AccessOptions, AccountPack, NewFolderOptions};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::Folder;
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
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
use sos_login::FolderKeys;
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
use {sos_backend::FileEventLog, sos_core::events::FileEvent};

pub enum ClientStorage {
    /// Filesystem storage.
    FileSystem(ClientFileStorage),
    /// Database storage.
    Database(ClientFileStorage), // TODO!: db storage
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientSecretStorage for ClientStorage {
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!()
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'_, VaultCommit>, ReadEvent)>> {
        todo!()
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        todo!()
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!()
    }

    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent> {
        todo!()
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!()
    }

    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent> {
        todo!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientFolderStorage for ClientStorage {
    fn folders(&self) -> &HashMap<VaultId, Folder> {
        todo!()
    }

    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder> {
        todo!()
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        todo!()
    }

    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)> {
        todo!()
    }

    async fn load_folders(&mut self) -> Result<&[Summary]> {
        todo!()
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        todo!()
    }

    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        todo!()
    }

    fn list_folders(&self) -> &[Summary] {
        todo!()
    }

    fn current_folder(&self) -> Option<Summary> {
        todo!()
    }

    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        todo!()
    }

    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        todo!()
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent> {
        todo!()
    }

    fn close_folder(&mut self) {
        todo!()
    }

    async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()> {
        todo!()
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        todo!()
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        todo!()
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        todo!()
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        todo!()
    }

    fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<()> {
        todo!()
    }

    fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()> {
        todo!()
    }

    async fn description(&self) -> Result<String> {
        todo!()
    }

    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent> {
        todo!()
    }

    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        todo!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientStorage {
    fn devices(&self) -> &IndexSet<TrustedDevice> {
        todo!()
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        todo!()
    }

    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        todo!()
    }

    async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        todo!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientAccountStorage for ClientStorage {
    fn account_id(&self) -> &AccountId {
        todo!()
    }

    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        todo!()
    }

    async fn lock(&mut self) {
        todo!()
    }

    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        todo!()
    }

    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        todo!()
    }

    fn paths(&self) -> Arc<Paths> {
        todo!()
    }

    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        todo!()
    }

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        todo!()
    }

    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        todo!()
    }

    async fn identity_state(&self) -> Result<CommitState> {
        todo!()
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        todo!()
    }

    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()> {
        todo!()
    }

    #[cfg(feature = "files")]
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    ) {
        todo!()
    }

    #[cfg(feature = "search")]
    fn index(&self) -> Result<&AccountSearch> {
        todo!()
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        todo!()
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        todo!()
    }

    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        todo!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        todo!()
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        todo!()
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        todo!()
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        todo!()
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        todo!()
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        todo!()
    }
}
