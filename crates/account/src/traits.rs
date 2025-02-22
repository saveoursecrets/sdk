//! Account storage and search index.
use crate::{convert::CipherComparison, Error};
use crate::{
    AccountChange, AccountData, DetachedView, FolderChange, FolderCreate,
    FolderDelete, SecretChange, SecretDelete, SecretInsert, SecretMove,
};
use indexmap::IndexSet;
use sos_backend::{BackendTarget, Folder};
use sos_client_storage::{AccessOptions, NewFolderOptions};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::{AccessKey, Cipher, KeyDerivation},
    device::{DevicePublicKey, TrustedDevice},
    events::{AccountEvent, DeviceEvent, EventRecord, ReadEvent, WriteEvent},
    AccountId, FolderRef, Paths, SecretId, UtcDateTime, VaultCommit, VaultId,
};
use sos_login::{
    device::{DeviceManager, DeviceSigner},
    PublicIdentity,
};
use sos_sync::CreateSet;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretPath, SecretRow},
    Summary, Vault, VaultFlags,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "search")]
use sos_search::{DocumentCount, SearchIndex};

#[cfg(feature = "archive")]
use sos_filesystem::archive::{Inventory, RestoreOptions};

#[cfg(feature = "search")]
use sos_search::*;

use async_trait::async_trait;
use secrecy::SecretString;
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use tokio::io::{AsyncRead, AsyncSeek};

#[cfg(feature = "contacts")]
use crate::ContactImportProgress;

#[cfg(feature = "clipboard")]
use {crate::ClipboardCopyRequest, xclipboard::Clipboard};

/// Trait for account implementations.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Account {
    /// Errors for this account.
    type Error: std::error::Error + std::fmt::Debug + From<Error>;

    /// Result type for network-aware implementations.
    type NetworkResult: std::fmt::Debug;

    /// Account identifier.
    fn account_id(&self) -> &AccountId;

    /// User storage paths.
    fn paths(&self) -> Arc<Paths>;

    /// Lookup a folder in the storage.
    async fn folder(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<Folder, Self::Error>;

    /// Determine if the account is authenticated.
    async fn is_authenticated(&self) -> bool;

    /// Import encrypted account events into the client storage.
    async fn import_account_events(
        &mut self,
        events: CreateSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Create a new in-memory device vault.
    ///
    /// The password for the vault is saved to the identity folder.
    async fn new_device_vault(
        &mut self,
    ) -> std::result::Result<(DeviceSigner, DeviceManager), Self::Error>;

    /// Signing key for the device.
    async fn device_signer(
        &self,
    ) -> std::result::Result<DeviceSigner, Self::Error>;

    /// Public key for the device signing key.
    async fn device_public_key(
        &self,
    ) -> std::result::Result<DevicePublicKey, Self::Error>;

    /// Patch the devices event log.
    async fn patch_devices_unchecked(
        &mut self,
        events: &[DeviceEvent],
    ) -> std::result::Result<(), Self::Error>;

    /// Revoke a device.
    async fn revoke_device(
        &mut self,
        device_key: &DevicePublicKey,
    ) -> std::result::Result<(), Self::Error>;

    /// Current device information.
    async fn current_device(
        &self,
    ) -> std::result::Result<TrustedDevice, Self::Error>;

    /// Collection of trusted devices.
    async fn trusted_devices(
        &self,
    ) -> std::result::Result<IndexSet<TrustedDevice>, Self::Error>;

    /// Public identity information.
    async fn public_identity(
        &self,
    ) -> std::result::Result<PublicIdentity, Self::Error>;

    /// Label of this account.
    async fn account_label(&self)
        -> std::result::Result<String, Self::Error>;

    /// Get the description of a folder.
    ///
    /// The target folder will become the currently open folder.
    async fn folder_description(
        &mut self,
        folder_id: &VaultId,
    ) -> std::result::Result<String, Self::Error>;

    /// Set the description of a folder.
    ///
    /// The target folder will become the currently open folder.
    async fn set_folder_description(
        &mut self,
        folder_id: &VaultId,
        description: impl AsRef<str> + Send + Sync,
    ) -> std::result::Result<FolderChange<Self::NetworkResult>, Self::Error>;

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to enroll other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the primary password for this account.
    async fn identity_vault_buffer(
        &self,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Summary of the identity folder for the account.
    async fn identity_folder_summary(
        &self,
    ) -> std::result::Result<Summary, Self::Error>;

    /// Reload the identity folder into memory.
    ///
    /// Can be used when changes to the identity folder
    /// have been made by external processes.
    async fn reload_identity_folder(
        &mut self,
    ) -> std::result::Result<(), Self::Error>;

    /// Change the cipher for an account.
    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> std::result::Result<CipherComparison, Self::Error>;

    /// Change the password for an account.
    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> std::result::Result<(), Self::Error>;

    /// Access an account by signing in.
    ///
    /// If a default folder exists for the account it is opened.
    async fn sign_in(
        &mut self,
        key: &AccessKey,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// Verify an access key for this account.
    ///
    /// If the account is not authenticated this returns false.
    async fn verify(&self, key: &AccessKey) -> bool;

    /// Open a folder.
    async fn open_folder(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<(), Self::Error>;

    /// Current open folder.
    async fn current_folder(
        &self,
    ) -> std::result::Result<Option<Summary>, Self::Error>;

    /// Try to find a folder using a predicate.
    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send;

    /// Try to find a folder by reference.
    async fn find_folder(&self, vault: &FolderRef) -> Option<Summary>;

    /// Find the default folder.
    async fn default_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_default()).await
    }

    /// Find the authenticator folder.
    async fn authenticator_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_authenticator()).await
    }

    /// Find the contacts folder.
    async fn contacts_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_contact()).await
    }

    /// Find the archive folder.
    async fn archive_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_archive()).await
    }

    /// History of events for a folder.
    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<
        Vec<(CommitHash, UtcDateTime, WriteEvent)>,
        Self::Error,
    >;

    /// Sign out of the account.
    async fn sign_out(&mut self) -> std::result::Result<(), Self::Error>;

    /// Rename this account.
    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> std::result::Result<AccountChange<Self::NetworkResult>, Self::Error>;

    /// Delete the account for this user and sign out.
    async fn delete_account(
        &mut self,
    ) -> std::result::Result<(), Self::Error>;

    /// Read the secret identifiers in a folder.
    async fn secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<Vec<SecretId>, Self::Error>;

    /// Load folders into memory.
    ///
    /// This method is automatically called on sign in to
    /// prepare the in-memory vaults but can be explicitly
    /// called to reload the data from disc.
    async fn load_folders(
        &mut self,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// List in-memory folders managed by this account.
    async fn list_folders(
        &self,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// Account data.
    async fn account_data(
        &self,
    ) -> std::result::Result<AccountData, Self::Error>;

    /// Root hash of the event log for a folder.
    async fn root_hash(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<CommitHash, Self::Error>;

    /// Commit state of the identity vault.
    ///
    /// The folder must have at least one commit.
    async fn identity_state(
        &self,
    ) -> std::result::Result<CommitState, Self::Error>;

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<CommitState, Self::Error>;

    /// Compact the identity folder and all user folders.
    async fn compact_account(
        &mut self,
    ) -> std::result::Result<HashMap<Summary, AccountEvent>, Self::Error>;

    /// Compact the event log file for a folder.
    async fn compact_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> std::result::Result<AccountEvent, Self::Error>;

    /// Restore a folder from an event log.
    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> std::result::Result<Summary, Self::Error>;

    /// Change the password for a folder.
    ///
    /// If this folder is part of a recovery pack it is
    /// the caller's responsbility to ensure the recovery
    /// pack is updated with the new folder password.
    async fn change_folder_password(
        &mut self,
        folder_id: &VaultId,
        new_key: AccessKey,
    ) -> std::result::Result<(), Self::Error>;

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        folder_id: &VaultId,
        commit: CommitHash,
    ) -> std::result::Result<DetachedView, Self::Error>;

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> std::result::Result<(DocumentCount, Vec<Summary>), Self::Error>;

    /// Compute the account statistics.
    ///
    /// If the account is not authenticated returns
    /// a default statistics object (all values will be zero).
    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics;

    /// Search index for the account.
    #[cfg(feature = "search")]
    async fn index(
        &self,
    ) -> std::result::Result<Arc<RwLock<SearchIndex>>, Self::Error>;

    /// Query with document views.
    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> std::result::Result<Vec<Document>, Self::Error>;

    /// Query the search index.
    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> std::result::Result<Vec<Document>, Self::Error>;

    /// Get the search index document count statistics.
    #[cfg(feature = "search")]
    async fn document_count(
        &self,
    ) -> std::result::Result<DocumentCount, Self::Error>;

    /// Determine if a document exists in a folder.
    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> std::result::Result<bool, Self::Error>;

    /// Decrypt a file and return the buffer.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Create a secret in the current open folder or a specific folder.
    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> std::result::Result<SecretChange<Self::NetworkResult>, Self::Error>;

    /// Bulk insert secrets into the currently open folder.
    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> std::result::Result<SecretInsert<Self::NetworkResult>, Self::Error>;

    /// Update a secret in the current open folder or a specific folder.
    ///
    /// If a `destination` is given the secret is also moved to the
    /// target folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
    ) -> std::result::Result<SecretChange<Self::NetworkResult>, Self::Error>;

    /// Move a secret between folders.
    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::NetworkResult>, Self::Error>;

    /// Read a secret in the current open folder.
    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> std::result::Result<(SecretRow, ReadEvent), Self::Error>;

    /// Read the encrypted contents of a secret.
    ///
    /// Does not affect the currently open folder and
    /// does not append any audit logs.
    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> std::result::Result<Option<(VaultCommit, ReadEvent)>, Self::Error>;

    /// Delete a secret and remove any external files.
    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretDelete<Self::NetworkResult>, Self::Error>;

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::NetworkResult>, Self::Error>;

    /// Move a secret out of the archive.
    ///
    /// The secret must be inside a folder with the archive flag set.
    ///
    /// If the secret is a contact and a contacts folder exists
    /// it is restored to the contacts folder.
    ///
    /// If the secret is a TOTP and an authenticator folder exists
    /// it is restored to the authenticator folder.
    ///
    /// Otherwise the secret is restored to the default folder.
    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> std::result::Result<
        (SecretMove<Self::NetworkResult>, Summary),
        Self::Error,
    >;

    /// Update a file secret.
    ///
    /// If the secret exists and is not a file secret it will be
    /// converted to a file secret so take care to ensure you only
    /// use this on file secrets.
    #[cfg(feature = "files")]
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
    ) -> std::result::Result<SecretChange<Self::NetworkResult>, Self::Error>;

    /// Create a folder.
    async fn create_folder(
        &mut self,
        options: NewFolderOptions,
    ) -> std::result::Result<FolderCreate<Self::NetworkResult>, Self::Error>;

    /// Rename a folder.
    async fn rename_folder(
        &mut self,
        folder_id: &VaultId,
        name: String,
    ) -> std::result::Result<FolderChange<Self::NetworkResult>, Self::Error>;

    /// Update folder flags.
    async fn update_folder_flags(
        &mut self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> std::result::Result<FolderChange<Self::NetworkResult>, Self::Error>;

    /// Import a folder from a vault file.
    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> std::result::Result<FolderCreate<Self::NetworkResult>, Self::Error>;

    /// Import a folder from a vault buffer.
    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> std::result::Result<FolderCreate<Self::NetworkResult>, Self::Error>;

    /// Import and overwrite the identity folder from a vault.
    ///
    /// This is used for destructive operations that rewrite the identity
    /// folder such as changing the cipher or account password.
    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> std::result::Result<AccountEvent, Self::Error>;

    /// Export a folder as a vault file.
    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> std::result::Result<(), Self::Error>;

    /// Export a folder to a buffer.
    async fn export_folder_buffer(
        &mut self,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> std::result::Result<FolderDelete<Self::NetworkResult>, Self::Error>;

    /// Forget a folder from in-memory collections.
    async fn forget_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> std::result::Result<bool, Self::Error>;

    /// Try to load an avatar JPEG image for a contact.
    ///
    /// Looks in the current open folder if no specified folder is given.
    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    /// Export a contact secret to a vCard file.
    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> std::result::Result<(), Self::Error>;

    /// Export all contacts to a single vCard.
    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> std::result::Result<(), Self::Error>;

    /// Import contacts from a vCard string buffer.
    ///
    /// The account must have a folder with the contacts
    /// flag.
    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> std::result::Result<Vec<SecretId>, Self::Error>;

    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> std::result::Result<(), Self::Error>;

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: sos_migrate::import::ImportTarget,
    ) -> std::result::Result<FolderCreate<Self::NetworkResult>, Self::Error>;

    /// Create a backup archive containing the
    /// encrypted data for the account.
    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> std::result::Result<(), Self::Error>;

    /// Read the inventory from an archive.
    #[cfg(feature = "archive")]
    async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    >(
        buffer: R,
    ) -> std::result::Result<Inventory, Self::Error>;

    /// Restore from a backup archive file.
    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        target: &BackendTarget,
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<Vec<PublicIdentity>, Self::Error>;

    /// Copy a secret to the clipboard.
    #[cfg(feature = "clipboard")]
    async fn copy_clipboard(
        &self,
        clipboard: &Clipboard,
        target: &SecretPath,
        request: &ClipboardCopyRequest,
    ) -> std::result::Result<bool, Self::Error>;
}
