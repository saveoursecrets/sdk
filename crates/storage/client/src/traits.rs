//! Client storage implementations.
use crate::{
    files::ExternalFileManager, AccessOptions, AccountPack, NewFolderOptions,
    Result, StorageChangeEvent,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::Folder;
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    device::{DevicePublicKey, TrustedDevice},
    events::{
        patch::FolderPatch, AccountEvent, DeviceEvent, Event, EventRecord,
        ReadEvent, WriteEvent,
    },
    AccountId, Paths, SecretId, UtcDateTime, VaultCommit, VaultFlags,
    VaultId,
};
use sos_login::FolderKeys;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    FolderRef, Summary, Vault,
};
use std::{borrow::Cow, collections::HashMap, sync::Arc};

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

/// Device management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientDeviceStorage {
    /// Collection of trusted devices.
    fn devices(&self) -> &IndexSet<TrustedDevice>;

    /// Set the collection of trusted devices.
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>);

    /// List trusted devices.
    fn list_trusted_devices(&self) -> Vec<&TrustedDevice>;

    /// Patch the devices event log.
    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()>;

    /// Revoke trust in a device.
    async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()>;
}

/// Folder management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientFolderStorage {
    /// In-memory folders.
    fn folders(&self) -> &HashMap<VaultId, Folder>;

    /// Mutable in-memory folders.
    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder>;

    /// Create a new folder.
    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)>;

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)>;

    /// Read folders from storage and create the in-memory
    /// event logs for each folder.
    async fn load_folders(&mut self) -> Result<&[Summary]>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>>;

    /// Remove a folder from the cache.
    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool>;

    /// List the in-memory folders.
    fn list_folders(&self) -> &[Summary];

    /// Currently open folder.
    fn current_folder(&self) -> Option<Summary>;

    /// Find a folder in this storage by reference.
    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary>;

    /// Find a folder in this storage using a predicate.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool;

    /// Mark a folder as the currently open folder.
    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent>;

    /// Close the current open folder.
    fn close_folder(&mut self);

    /// Create folders from a collection of folder patches.
    ///
    /// If the folders already exist they will be overwritten.
    async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()>;

    /// Compact an event log file.
    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent>;

    /// Restore a folder from an event log.
    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary>;

    /// Set the name of a folder.
    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event>;

    /// Update the flags for a folder.
    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event>;

    /// Update the in-memory name for a folder.
    fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<()>;

    /// Update the in-memory name for a folder.
    fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()>;

    /// Get the description of the currently open folder.
    async fn description(&self) -> Result<String>;

    /// Set the description of the currently open folder.
    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent>;

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey>;
}

/// Secret management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientSecretStorage {
    /// Create a secret in the currently open vault.
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Read the encrypted contents of a secret.
    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'_, VaultCommit>, ReadEvent)>>;

    /// Read a secret in the currently open folder.
    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)>;

    /// Update a secret in the currently open folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Write a secret in the current open folder.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent>;

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent>;
}

/// Trait for client storage implementations.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientAccountStorage:
    ClientDeviceStorage + ClientFolderStorage + ClientSecretStorage
// TODO: + SyncStorage
{
    /// Account identifier.
    fn account_id(&self) -> &AccountId;

    /// Determine if the storage is authenticated.
    async fn is_authenticated(&self) -> bool;

    /// Import an identity vault and generate the event but
    /// do not write the event to the account event log.
    ///
    /// This is used when merging account event logs to ensure
    /// the `AccountEvent::UpdateIdentity` event is not duplicated.
    ///
    /// Typically the handlers that update storage but don't append log
    /// events are declared in the storage implementation but the
    /// identity log is managed by the account so this must exist here.
    #[doc(hidden)]
    async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent>;

    /// Unlock all folders.
    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()>;

    /// Lock all folders.
    async fn lock(&mut self);

    /// Unlock a folder.
    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()>;

    /// Lock a folder.
    async fn lock_folder(&mut self, id: &VaultId) -> Result<()>;

    /// Computed storage paths.
    fn paths(&self) -> Arc<Paths>;

    /// Create the data for a new account.
    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>>;

    /// Read a vault from the storage.
    async fn read_vault(&self, id: &VaultId) -> Result<Vault>;

    /// Get the history of events for a vault.
    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>>;

    /// Commit state of the identity folder.
    async fn identity_state(&self) -> Result<CommitState>;

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(&self, summary: &Summary) -> Result<CommitState>;

    /// Restore vaults from an archive.
    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()>;

    /// Set the password for file encryption.
    #[cfg(feature = "files")]
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    );

    /// External file manager.
    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> &ExternalFileManager;

    /// Mutable external file manager.
    #[cfg(feature = "files")]
    fn external_file_manager_mut(&mut self) -> &mut ExternalFileManager;

    /// Search index reference.
    #[cfg(feature = "search")]
    fn index(&self) -> Result<&AccountSearch>;

    /// Mutable search index reference.
    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch>;

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)>;

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount>;
}
