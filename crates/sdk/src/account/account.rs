//! Account storage and search index.
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    account::{
        convert::{CipherConversion, ConvertCipher},
        AccountBuilder,
    },
    commit::{CommitHash, CommitState},
    crypto::{AccessKey, Cipher, KeyDerivation},
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, Event, EventKind, EventLogExt,
        FolderReducer, ReadEvent, WriteEvent,
    },
    identity::{AccountRef, FolderKeys, Identity, PublicIdentity},
    signer::ecdsa::{Address, BoxedEcdsaSigner},
    storage::AccountPack,
    storage::{
        search::{DocumentCount, SearchIndex},
        AccessOptions, ClientStorage,
    },
    sync::SyncStorage,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretType},
        Gatekeeper, Header, Summary, Vault, VaultId,
    },
    vfs, Error, Paths, Result, UtcDateTime,
};

#[cfg(feature = "audit")]
use crate::audit::{AuditData, AuditEvent};

#[cfg(feature = "archive")]
use crate::account::archive::{Inventory, RestoreOptions};

#[cfg(feature = "device")]
use crate::device::{
    DeviceManager, DevicePublicKey, DeviceSigner, TrustedDevice,
};

#[cfg(feature = "device")]
use indexmap::IndexSet;

#[cfg(feature = "search")]
use crate::storage::search::*;

#[cfg(feature = "sync")]
use crate::sync::SyncError;

#[cfg(all(feature = "files", feature = "sync"))]
use crate::storage::files::Transfers;

#[cfg(feature = "security-report")]
use crate::{account::security_report::*, zxcvbn::Entropy};

#[cfg(feature = "migrate")]
use crate::{
    migrate::{
        export::PublicExport,
        import::{
            csv::{
                bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
                dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
                macos::MacPasswordCsv, one_password::OnePasswordCsv,
            },
            ImportFormat, ImportTarget,
        },
        Convert,
    },
    vault::{BuilderCredentials, VaultBuilder},
};

use tracing::{span, Level};

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncSeek, BufReader},
    sync::RwLock,
};

/// Result information for a created or updated secret.
pub struct SecretChange<T: std::error::Error> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was created (or updated).
    pub commit_state: CommitState,
    /// Folder containing the secret.
    pub folder: Summary,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for a bulk insert.
pub struct SecretInsert<T: std::error::Error> {
    /// Created secrets.
    pub results: Vec<SecretChange<T>>,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for a secret move event.
pub struct SecretMove<T: std::error::Error> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for a deleted secret.
pub struct SecretDelete<T: std::error::Error> {
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was deleted.
    pub commit_state: CommitState,
    /// Folder the secret was deleted from.
    pub folder: Summary,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for folder creation.
pub struct FolderCreate<T: std::error::Error> {
    /// Created folder.
    pub folder: Summary,
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the new folder.
    pub commit_state: CommitState,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for changes to a folder's attributes.
pub struct FolderChange<T: std::error::Error> {
    /// Event to be logged.
    pub event: Event,
    /// Commit state before the change.
    pub commit_state: CommitState,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Result information for folder deletion.
pub struct FolderDelete<T: std::error::Error> {
    /// Events to be logged.
    pub events: Vec<Event>,
    /// Commit state of the folder.
    pub commit_state: CommitState,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
    #[doc(hidden)]
    pub marker: std::marker::PhantomData<T>,
}

/// Progress event when importing contacts.
#[cfg(feature = "contacts")]
pub enum ContactImportProgress {
    /// Progress event when the number of contacts is known.
    Ready {
        /// Total number of contacts.
        total: usize,
    },
    /// Progress event when a contact is being imported.
    Item {
        /// Label of the contact.
        label: String,
        /// Index of the contact.
        index: usize,
    },
}

/// Trait for account implementations.
#[async_trait]
pub trait Account {
    /// Account type to create.
    type Account;

    /// Errors for this account.
    type Error: std::error::Error + std::fmt::Debug;

    /// Account address.
    fn address(&self) -> &Address;

    /// User storage paths.
    fn paths(&self) -> Arc<Paths>;

    /// Determine if the account is authenticated.
    async fn is_authenticated(&self) -> bool;

    /// Signing key for the account.
    async fn account_signer(
        &self,
    ) -> std::result::Result<BoxedEcdsaSigner, Self::Error>;

    /// Create a new in-memory device vault.
    ///
    /// The password for the vault is saved to the identity folder.
    #[cfg(feature = "device")]
    async fn new_device_vault(
        &mut self,
    ) -> std::result::Result<(DeviceSigner, DeviceManager), Self::Error>;

    /// Signing key for the device.
    #[cfg(feature = "device")]
    async fn device_signer(
        &self,
    ) -> std::result::Result<DeviceSigner, Self::Error>;

    /// Public key for the device signing key.
    #[cfg(feature = "device")]
    async fn device_public_key(
        &self,
    ) -> std::result::Result<DevicePublicKey, Self::Error>;

    /// Current device information.
    #[cfg(feature = "device")]
    async fn current_device(
        &self,
    ) -> std::result::Result<TrustedDevice, Self::Error>;

    /// Collection of trusted devices.
    #[cfg(feature = "device")]
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
        folder: &Summary,
    ) -> std::result::Result<String, Self::Error>;

    /// Set the description of a folder.
    ///
    /// The target folder will become the currently open folder.
    async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str> + Send + Sync,
    ) -> std::result::Result<FolderChange<Self::Error>, Self::Error>;

    /// Find the password for a folder.
    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<AccessKey, Self::Error>;

    /// Generate the password for a folder.
    async fn generate_folder_password(
        &self,
    ) -> std::result::Result<SecretString, Self::Error>;

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

    /// Change the cipher for an account.
    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> std::result::Result<CipherConversion, Self::Error>;

    /// Access an account by signing in.
    ///
    /// If a default folder exists for the account it
    /// is opened.
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
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<(), Self::Error>;

    /// Try to find a folder using a predicate.
    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send;

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

    /// Sign out of the account.
    async fn sign_out(&mut self) -> std::result::Result<(), Self::Error>;

    /// Rename this account.
    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> std::result::Result<(), Self::Error>;

    /// Delete the account for this user and sign out.
    async fn delete_account(
        &mut self,
    ) -> std::result::Result<(), Self::Error>;

    /// Storage provider.
    async fn storage(
        &self,
    ) -> std::result::Result<Arc<RwLock<ClientStorage>>, Self::Error>;

    /// Read the secret identifiers in a vault.
    async fn secret_ids(
        &self,
        summary: &Summary,
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

    /// Root commit hash for a folder.
    async fn root_commit(
        &self,
        summary: &Summary,
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
        summary: &Summary,
    ) -> std::result::Result<CommitState, Self::Error>;

    /// Compact the event log file for a folder.
    async fn compact(
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<(u64, u64), Self::Error>;

    /// Change the password for a folder.
    ///
    /// If this folder is part of a recovery pack it is
    /// the caller's responsbility to ensure the recovery
    /// pack is updated with the new folder password.
    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> std::result::Result<(), Self::Error>;

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> std::result::Result<DetachedView, Self::Error>;

    /// Transfers queue.
    #[cfg(all(feature = "files", feature = "sync"))]
    async fn transfers(
        &self,
    ) -> std::result::Result<Arc<RwLock<Transfers>>, Self::Error>;

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
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
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
    ) -> std::result::Result<SecretChange<Self::Error>, Self::Error>;

    /// Bulk insert secrets into the currently open folder.
    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> std::result::Result<SecretInsert<Self::Error>, Self::Error>;

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
        destination: Option<&Summary>,
    ) -> std::result::Result<SecretChange<Self::Error>, Self::Error>;

    /// Move a secret between folders.
    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::Error>, Self::Error>;

    /// Read a secret in the current open folder.
    async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> std::result::Result<(SecretRow, ReadEvent), Self::Error>;

    /// Delete a secret and remove any external files.
    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretDelete<Self::Error>, Self::Error>;

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::Error>, Self::Error>;

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
    ) -> std::result::Result<(SecretMove<Self::Error>, Summary), Self::Error>;

    /// Update a file secret.
    ///
    /// If the secret exists and is not a file secret it will be
    /// converted to a file secret so take care to ensure you only
    /// use this on file secrets.
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> std::result::Result<SecretChange<Self::Error>, Self::Error>;

    /// Create a folder.
    async fn create_folder(
        &mut self,
        name: String,
    ) -> std::result::Result<FolderCreate<Self::Error>, Self::Error>;

    /// Rename a folder.
    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> std::result::Result<FolderChange<Self::Error>, Self::Error>;

    /// Import a folder from a vault file.
    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> std::result::Result<FolderCreate<Self::Error>, Self::Error>;

    /// Import a folder from a vault buffer.
    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> std::result::Result<FolderCreate<Self::Error>, Self::Error>;

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
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> std::result::Result<(), Self::Error>;

    /// Export a folder to a buffer.
    async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<FolderDelete<Self::Error>, Self::Error>;

    /// Try to load an avatar JPEG image for a contact.
    ///
    /// Looks in the current open folder if no specified folder is given.
    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    /// Export a contact secret to a vCard file.
    #[cfg(feature = "contacts")]
    async fn export_contact(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> std::result::Result<(), Self::Error>;

    /// Export all contacts to a single vCard.
    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &mut self,
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

    /// Generate a security report.
    #[cfg(feature = "security-report")]
    async fn generate_security_report<T, D, R>(
        &mut self,
        options: SecurityReportOptions<T, D, R>,
    ) -> std::result::Result<SecurityReport<T>, Self::Error>
    where
        D: Fn(Vec<String>) -> R + Send + Sync,
        R: std::future::Future<Output = Vec<T>> + Send + Sync;

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
        target: ImportTarget,
    ) -> std::result::Result<FolderCreate<Self::Error>, Self::Error>;

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
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<PublicIdentity, Self::Error>;

    /// Restore from a backup archive file.
    #[cfg(feature = "archive")]
    async fn restore_backup_archive(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        password: SecretString,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<PublicIdentity, Self::Error>;
}

/// Read-only view created from a specific event log commit.
pub struct DetachedView {
    keeper: Gatekeeper,
    index: Arc<RwLock<SearchIndex>>,
}

impl DetachedView {
    /// Read-only access to the folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Search index for the detached view.
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.index)
    }
}

/// Data about an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// Main account information.
    #[serde(flatten)]
    pub account: PublicIdentity,
    /// AGE identity public recipient.
    pub identity: String,
    /// Account folders.
    pub folders: Vec<Summary>,
    /*
    #[cfg(feature = "device")]
    /// Address of the device public key.
    pub device_address: String,
    */
}

/// Account information when signed in.
pub(super) struct Authenticated {
    /// Authenticated user.
    pub(super) user: Identity,

    /// Storage provider.
    storage: Arc<RwLock<ClientStorage>>,
}

/// User account backed by the filesystem.
///
/// Many functions require that the account is authenticated and will
/// return [Error::NotAuthenticated] if the account is not authenticated
/// to authenticate a user call [Account::sign_in].
pub struct LocalAccount {
    /// Account address.
    address: Address,

    /// Account information after a successful
    /// sign in.
    pub(super) authenticated: Option<Authenticated>,

    /// Storage paths.
    paths: Arc<Paths>,
}

impl LocalAccount {
    /// Authenticated user information.
    pub(super) fn user(&self) -> Result<&Identity> {
        self.authenticated
            .as_ref()
            .map(|a| &a.user)
            .ok_or(Error::NotAuthenticated)
    }

    /// Mutable authenticated user information.
    pub(super) fn user_mut(&mut self) -> Result<&mut Identity> {
        self.authenticated
            .as_mut()
            .map(|a| &mut a.user)
            .ok_or(Error::NotAuthenticated)
    }

    async fn initialize_account_log(
        paths: &Paths,
        account_log: Arc<RwLock<AccountEventLog>>,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "init_account_log");
        let _enter = span.enter();

        let mut event_log = account_log.write().await;
        let needs_init = event_log.tree().root().is_none();

        tracing::debug!(needs_init = %needs_init);

        // If the account event log does not already exist
        // we initialize it from the current state on disc
        // adding create folder events for every folder that
        // already exists
        if needs_init {
            let folders: Vec<Summary> = Identity::list_local_folders(paths)
                .await?
                .into_iter()
                .map(|(s, _)| s)
                .collect();

            let mut events = Vec::new();

            for folder in folders {
                let buffer = vfs::read(paths.vault_path(folder.id())).await?;
                let vault: Vault = decode(&buffer).await?;
                let header: Header = vault.into();
                let head_only: Vault = header.into();
                let buffer = encode(&head_only).await?;
                events
                    .push(AccountEvent::CreateFolder(folder.into(), buffer));
            }

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(())
    }

    /// Export a vault by changing the vault passphrase and
    /// converting it to a buffer.
    ///
    /// The identity vault must be unlocked so we can retrieve
    /// the passphrase for the target vault.
    async fn change_vault_password(
        &self,
        vault_id: &VaultId,
        new_key: AccessKey,
    ) -> Result<Vec<u8>> {
        use crate::passwd::ChangePassword;
        let paths = self.paths().clone();
        // Get the current vault passphrase from the identity vault
        let current_key = self.user()?.find_folder_password(vault_id).await?;

        // Find the local vault for the account
        let (vault, _) = Identity::load_local_vault(&paths, vault_id).await?;

        // Change the password before exporting
        let (_, vault, _) =
            ChangePassword::new(&vault, current_key, new_key, None)
                .build()
                .await?;

        encode(&vault).await
    }

    pub(crate) async fn open_vault(
        &mut self,
        summary: &Summary,
        audit: bool,
    ) -> Result<()> {
        // Bail early if the folder is already open
        {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            if let Some(current) = reader.current_folder() {
                if current.id() == summary.id() {
                    return Ok(());
                }
            }
        }

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.open_folder(summary).await?
        };

        if audit {
            let event = Event::Read(*summary.id(), event);
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Helper to get all the state information needed
    /// before calling sync methods.
    ///
    /// Computes the target folder that will be used, the last commit
    /// hash and the proof for the current head of the events log.
    async fn compute_folder_state(
        &self,
        options: &AccessOptions,
    ) -> Result<(Summary, CommitState)> {
        let (folder, commit_state) = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            let folder = options
                .folder
                .clone()
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?;

            let commit_state = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?
                .commit_state()
                .await?;

            (folder, commit_state)
        };
        Ok((folder, commit_state))
    }

    /// Import an identity vault and generate the event but
    /// do not write the event to the account event log.
    ///
    /// This is used when merging account event logs to ensure
    /// the `AccountEvent::UpdateIdentity` event is not duplicated.
    ///
    /// Typically the handlers that update storage but don't append log
    /// events are declared in the storage implementation but the
    /// identity log is managed by the account so this must exist here.
    pub(super) async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let span = span!(Level::DEBUG, "import_identity_vault");
        let _enter = span.enter();

        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        // Update the identity vault
        let buffer = encode(&vault).await?;
        let identity_vault_path = self.paths().identity_vault();
        vfs::write(&identity_vault_path, &buffer).await?;

        // Update the events for the identity vault
        let user = self.user()?;
        let identity = user.identity()?;
        let event_log = identity.event_log();
        let mut event_log = event_log.write().await;
        event_log.clear().await?;

        let (_, events) = FolderReducer::split(vault).await?;
        event_log.apply(events.iter().collect()).await?;

        Ok(AccountEvent::UpdateIdentity(buffer))
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        mut options: AccessOptions,
        audit: bool,
    ) -> Result<(SecretId, Event, Summary)> {
        let folder = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            options
                .folder
                .take()
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let id = SecretId::new_v4();
        let secret_data = SecretRow::new(id, meta, secret);
        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.create_secret(secret_data, options).await?
        };

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok((id, event, folder))
    }

    /// Get a secret in the current open folder and
    /// optionally append to the audit log.
    ///
    /// Some internal operations needn't generate extra
    /// audit log records.
    pub(crate) async fn get_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<(SecretRow, ReadEvent)> {
        let folder = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let (meta, secret, read_event) = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.read_secret(secret_id).await?
        };

        if audit {
            let event = Event::Read(*folder.id(), read_event.clone());
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok((SecretRow::new(*secret_id, meta, secret), read_event))
    }

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        mut options: AccessOptions,
    ) -> Result<SecretMove<Error>> {
        self.open_vault(from, false).await?;
        let (secret_data, read_event) =
            self.get_secret(secret_id, None, false).await?;
        let move_secret_data = secret_data.clone();

        self.open_vault(to, false).await?;
        let (new_id, create_event, _) = self
            .add_secret(
                secret_data.meta,
                secret_data.secret,
                Default::default(),
                false,
            )
            .await?;
        self.open_vault(from, false).await?;

        // Note that we call `remove_secret()` and not `delete_secret()`
        // as we need the original external files for the
        // move_files operation.
        let delete_event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.remove_secret(secret_id).await?
        };

        #[cfg(feature = "files")]
        {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;

            let events = writer
                .move_files(
                    &move_secret_data,
                    from.id(),
                    to.id(),
                    secret_id,
                    &new_id,
                    None,
                    &mut options.file_progress,
                )
                .await?;
            writer.append_file_mutation_events(&events).await?;
        }

        let (_, create_event) = create_event.try_into()?;
        //let (_, delete_event) = delete_event.try_into()?;

        let event = Event::MoveSecret(read_event, create_event, delete_event);

        let audit_event = AuditEvent::new(
            EventKind::MoveSecret,
            *self.address(),
            Some(AuditData::MoveSecret {
                from_vault_id: *from.id(),
                to_vault_id: *to.id(),
                from_secret_id: *secret_id,
                to_secret_id: new_id,
            }),
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(SecretMove {
            id: new_id,
            event,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    pub(crate) async fn build_search_index(
        &mut self,
    ) -> Result<DocumentCount> {
        let keys = self.folder_keys().await?;
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.build_search_index(&keys).await
    }

    /// Access keys for all folders.
    pub(super) async fn folder_keys(&self) -> Result<FolderKeys> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let folders = reader.list_folders();
        let mut keys = HashMap::new();
        for folder in folders {
            keys.insert(
                folder.clone(),
                self.user()?.find_folder_password(folder.id()).await?,
            );
        }
        Ok(FolderKeys(keys))
    }

    /// Generic CSV import implementation.
    #[cfg(feature = "migrate")]
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<FolderCreate<Error>> {
        let paths = self.paths();

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ImportUnsafe,
                self.address().clone(),
                None,
            );
            paths.append_audit_events(vec![audit_event]).await?;
        }

        let vaults = Identity::list_local_folders(&paths).await?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == folder_name);

        let vault_passphrase = self.user()?.generate_folder_password()?;

        let vault_id = VaultId::new_v4();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault_id)
        } else {
            folder_name
        };

        let vault = VaultBuilder::new()
            .id(vault_id)
            .public_name(name)
            .build(BuilderCredentials::Password(
                vault_passphrase.clone(),
                None,
            ))
            .await?;

        // Parse the CSV records into the vault
        let key = vault_passphrase.clone().into();
        let vault = converter
            .convert(path.as_ref().to_path_buf(), vault, &key)
            .await?;

        let buffer = encode(&vault).await?;
        let key: AccessKey = vault_passphrase.clone().into();
        let result = self.import_folder_buffer(&buffer, key, false).await?;

        self.user_mut()?
            .save_folder_password(vault.id(), vault_passphrase.clone().into())
            .await?;

        Ok(result)
    }

    /// Import from an archive reader.
    #[cfg(feature = "archive")]
    async fn import_archive_reader<R: AsyncRead + AsyncSeek + Unpin>(
        buffer: R,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        use super::archive::{AccountBackup, ExtractFilesLocation};
        let files_dir = ExtractFilesLocation::Builder(Box::new(|address| {
            let data_dir = Paths::data_dir().unwrap();
            let paths = Paths::new(data_dir, address);
            Some(paths.files_dir().to_owned())
        }));

        options.files_dir = Some(files_dir);

        let (_, account) = AccountBackup::import_archive_reader(
            BufReader::new(buffer),
            options,
            data_dir,
        )
        .await?;

        Ok(account)
    }
}

impl From<&LocalAccount> for AccountRef {
    fn from(value: &LocalAccount) -> Self {
        Self::Address(*value.address())
    }
}

impl LocalAccount {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let paths = Paths::new_global(data_dir);

        Ok(Self {
            address,
            paths: Arc::new(paths),
            authenticated: None,
        })
    }

    /// Create a new account with the given
    /// name, passphrase and provider.
    ///
    /// Uses standard flags for the account builder for
    /// more control of the created account use
    /// `new_account_with_builder()`.
    pub async fn new_account(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            data_dir,
            |builder| builder.create_file_password(true),
        )
        .await
    }

    /// Create a new account with the given
    /// name, passphrase and provider and modify the
    /// account builder.
    pub async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
    ) -> Result<Self> {
        let span = span!(Level::DEBUG, "new_account");
        let _enter = span.enter();

        let account_builder = builder(AccountBuilder::new(
            account_name,
            passphrase.clone(),
            data_dir.clone(),
        ));
        let new_account = account_builder.finish().await?;

        tracing::debug!(address = %new_account.address, "created account");

        let address = new_account.address;
        let identity_log = new_account.user.identity()?.event_log();

        let mut storage = ClientStorage::new(
            address,
            data_dir.clone(),
            identity_log,
            #[cfg(feature = "device")]
            new_account.user.identity()?.devices()?.current_device(None),
        )
        .await?;

        tracing::debug!("prepared storage provider");

        // Must import the new account before signing in
        let public_account: AccountPack = new_account.into();
        storage.create_account(&public_account).await?;

        tracing::debug!("imported new account");

        let account = Self {
            address,
            paths: storage.paths(),
            authenticated: None,
        };

        Ok(account)
    }
}

#[async_trait]
impl Account for LocalAccount {
    type Account = LocalAccount;
    type Error = Error;

    fn address(&self) -> &Address {
        &self.address
    }

    fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
    }

    async fn is_authenticated(&self) -> bool {
        self.authenticated.is_some()
    }

    async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        Ok(self.user()?.identity()?.signer().clone())
    }

    #[cfg(feature = "device")]
    async fn device_signer(&self) -> Result<DeviceSigner> {
        Ok(self.user()?.identity()?.device().clone())
    }

    #[cfg(feature = "device")]
    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        let paths = Arc::clone(&self.paths);
        let signer = DeviceSigner::new_random();
        let manager = self
            .user_mut()?
            .identity_mut()?
            .create_device_vault(&*paths, signer.clone(), false)
            .await?;
        Ok((signer, manager))
    }

    #[cfg(feature = "device")]
    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        Ok(self.user()?.identity()?.device().public_key())
    }

    #[cfg(feature = "device")]
    async fn current_device(&self) -> Result<TrustedDevice> {
        Ok(self
            .authenticated
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .user
            .devices()?
            .current_device(None))
    }

    #[cfg(feature = "device")]
    async fn trusted_devices(&self) -> Result<IndexSet<TrustedDevice>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.devices().clone())
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        Ok(self.user()?.account()?.clone())
    }

    async fn account_label(&self) -> Result<String> {
        Ok(self.user()?.account()?.label().to_owned())
    }

    async fn folder_description(
        &mut self,
        folder: &Summary,
    ) -> Result<String> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        self.open_folder(folder).await?;
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.description().await?)
    }

    async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::Error>> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        self.open_folder(folder).await?;

        let options = AccessOptions {
            folder: Some(folder.clone()),
            ..Default::default()
        };
        let (_, commit_state) = self.compute_folder_state(&options).await?;

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.set_description(description).await?
        };

        let event = Event::Write(*folder.id(), event);

        Ok(FolderChange {
            event,
            commit_state,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<AccessKey> {
        Ok(self.user()?.find_folder_password(folder_id).await?)
    }

    async fn generate_folder_password(&self) -> Result<SecretString> {
        Ok(self.user()?.generate_folder_password()?)
    }

    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let identity_path = reader.paths().identity_vault();
        Ok(vfs::read(identity_path).await?)
    }

    async fn identity_folder_summary(&self) -> Result<Summary> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        Ok(self.user()?.identity()?.vault().summary().clone())
    }

    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherConversion> {
        let conversion = ConvertCipher::build(self, &cipher, kdf).await?;

        // Short circuit if there is nothing to do
        if conversion.is_empty() {
            return Ok(conversion);
        }

        ConvertCipher::convert(self, &conversion, account_key).await?;

        // Login again so in-memory data is up to date
        let identity_vault_path = self.paths().identity_vault();
        self.user_mut()?
            .login(&identity_vault_path, &account_key)
            .await?;

        Ok(conversion)
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let span = span!(Level::DEBUG, "sign_in");
        let _enter = span.enter();

        let address = &self.address;
        let data_dir = self.paths().documents_dir().clone();

        tracing::debug!(address = %address);

        // Ensure all paths before sign_in
        let paths = Paths::new(&data_dir, address.to_string());
        paths.ensure().await?;

        tracing::debug!(data_dir = ?paths.documents_dir());

        let mut user = Identity::new(paths.clone());
        user.sign_in(self.address(), key).await?;
        tracing::debug!("sign in success");

        // Signing key for the storage provider
        let signer = user.identity()?.signer().clone();

        let identity_log = user.identity().as_ref().unwrap().event_log();

        let mut storage = ClientStorage::new(
            signer.address()?,
            Some(data_dir),
            identity_log,
            #[cfg(feature = "device")]
            user.identity()?.devices()?.current_device(None),
        )
        .await?;
        self.paths = storage.paths();

        let file_password = user.find_file_encryption_password().await?;
        storage.set_file_password(Some(file_password));

        Self::initialize_account_log(
            &self.paths,
            Arc::clone(&storage.account_log),
        )
        .await?;

        self.authenticated = Some(Authenticated {
            user,
            storage: Arc::new(RwLock::new(storage)),
        });

        // Load vaults into memory and initialize folder
        // event log commit trees
        let folders = self.load_folders().await?;

        // Unlock all the storage vaults
        {
            let folder_keys = self.folder_keys().await?;
            let storage = self.storage().await?;
            let mut storage = storage.write().await;
            storage.unlock(&folder_keys).await?;
        }

        if let Some(default_folder) = self.default_folder().await {
            self.open_folder(&default_folder).await?;
        }

        Ok(folders)
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(auth) = &self.authenticated {
            auth.user.verify(key).await
        } else {
            false
        }
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        self.open_vault(summary, true).await
    }

    async fn sign_out(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());

        tracing::debug!("lock storage vaults");
        // Lock all the storage vaults
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.lock().await;

        tracing::debug!("clear search index");
        // Remove the search index
        writer.index_mut()?.clear().await;

        tracing::debug!("sign out user identity");
        // Forget private identity information
        self.user_mut()?.sign_out().await?;

        tracing::debug!("remove authenticated state");
        self.authenticated = None;

        Ok(())
    }

    async fn rename_account(&mut self, account_name: String) -> Result<()> {
        Ok(self.user_mut()?.rename_account(account_name).await?)
    }

    async fn delete_account(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "delete_account");
        let _enter = span.enter();

        let paths = self.paths().clone();
        let event = self.user_mut()?.delete_account(&paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;
        self.sign_out().await?;
        Ok(())
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        if let Some(auth) = &self.authenticated {
            let reader = auth.storage.read().await;
            reader.find(predicate).cloned()
        } else {
            None
        }
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        let auth =
            self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        Ok(Arc::clone(&auth.storage))
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let vault: Vault = reader.read_vault(summary.id()).await?;
        Ok(vault.keys().cloned().collect())
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        tracing::debug!("load folders");
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        Ok(writer.load_folders().await?.to_vec())
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.list_folders().to_vec())
    }

    async fn account_data(&self) -> Result<AccountData> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let user = self.user()?;
        Ok(AccountData {
            account: user.account()?.clone(),
            identity: user
                .identity()?
                .private_identity()
                .recipient()
                .to_string(),
            folders: reader.list_folders().to_vec(),
        })
    }

    async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let folder = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().root().ok_or_else(|| Error::NoRootCommit)?)
    }

    async fn identity_state(&self) -> Result<CommitState> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.identity_state().await?)
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.commit_state(summary).await?)
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let key = self.user()?.find_folder_password(summary.id()).await?;

        let (old_size, new_size) = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.compact(summary, &key).await?
        };

        Ok((old_size, new_size))
    }

    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let current_key =
            self.user()?.find_folder_password(folder.id()).await?;

        let vault = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            reader.read_vault(folder.id()).await?
        };

        {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer
                .change_password(&vault, current_key, new_key.clone())
                .await?;
        }

        // Save the new password
        self.user_mut()?
            .save_folder_password(folder.id(), new_key)
            .await?;

        Ok(())
    }

    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));

        let storage = self.storage().await?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let folder = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;

        let key = self.user()?.find_folder_password(summary.id()).await?;

        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let vault = FolderReducer::new_until_commit(commit)
            .reduce(&log_file)
            .await?
            .build(true)
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&key).await?;

        {
            let mut index = search_index.write().await;
            index.add_folder(&keeper).await?;
        }

        Ok(DetachedView {
            keeper,
            index: search_index,
        })
    }

    #[cfg(all(feature = "files", feature = "sync"))]
    async fn transfers(&self) -> Result<Arc<RwLock<Transfers>>> {
        let storage = self.storage().await?;
        let storage = storage.read().await;
        Ok(storage.transfers())
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let keys = self.folder_keys().await?;
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.initialize_search_index(&keys).await
    }

    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        if self.authenticated.is_some() {
            let storage = self.storage().await.unwrap();
            let reader = storage.read().await;
            if let Ok(index) = reader.index() {
                let search_index = index.search();
                let index = search_index.read().await;
                let statistics = index.statistics();
                let count = statistics.count();

                let documents: usize = count.vaults().values().sum();
                let mut folders = Vec::new();
                let mut types = HashMap::new();

                for (id, v) in count.vaults() {
                    if let Some(summary) = self.find(|s| s.id() == id).await {
                        folders.push((summary, *v));
                    }
                }

                for (k, v) in count.kinds() {
                    if let Ok(kind) = SecretType::try_from(*k) {
                        types.insert(kind, *v);
                    }
                }

                AccountStatistics {
                    documents,
                    folders,
                    types,
                    tags: count.tags().clone(),
                    favorites: count.favorites(),
                }
            } else {
                Default::default()
            }
        } else {
            Default::default()
        }
    }

    #[cfg(feature = "search")]
    async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.index()?.search())
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.index()?.query_view(views, archive).await
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.index()?.query_map(query, filter).await
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.statistics().count().clone())
    }

    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.find_by_label(vault_id, label, id).is_some())
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.download_file(vault_id, secret_id, file_name).await
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        let (id, event, _) =
            self.add_secret(meta, secret, options, true).await?;

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::Error>> {
        let mut results = Vec::new();
        for (meta, secret) in secrets {
            results.push(
                self.create_secret(meta, secret, Default::default()).await?,
            );
        }
        Ok(SecretInsert {
            results,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(&folder).await?;

        if let Some(Secret::Pem { certificates, .. }) = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer
                .update_secret(secret_id, meta, secret, options.clone())
                .await?
        };

        let event = Event::Write(*folder.id(), event);

        let id = if let Some(to) = destination.as_ref() {
            let SecretMove { id, .. } =
                self.mv_secret(secret_id, &folder, to, options).await?;
            id
        } else {
            *secret_id
        };

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.get_secret(secret_id, folder, true).await
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(&folder).await?;

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.delete_secret(secret_id, options).await?
        };

        let event = Event::Write(*folder.id(), event);

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(SecretDelete {
            event,
            commit_state,
            folder,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
        if from.flags().is_archive() {
            return Err(Error::AlreadyArchived);
        }
        self.open_folder(from).await?;
        let to = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        self.move_secret(secret_id, from, &to, options).await
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::Error>, Summary)> {
        let from = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        if !from.flags().is_archive() {
            return Err(Error::NotArchived);
        }
        self.open_folder(&from).await?;
        let mut to = self
            .default_folder()
            .await
            .ok_or_else(|| Error::NoDefaultFolder)?;
        let authenticator = self.authenticator_folder().await;
        let contacts = self.contacts_folder().await;
        if secret_meta.kind() == &SecretType::Totp && authenticator.is_some()
        {
            to = authenticator.unwrap();
        } else if secret_meta.kind() == &SecretType::Contact
            && contacts.is_some()
        {
            to = contacts.unwrap();
        }
        let result = self.move_secret(secret_id, &from, &to, options).await?;
        Ok((result, to))
    }

    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::Error>> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(
            secret_id,
            meta,
            Some(secret),
            options,
            destination,
        )
        .await
    }

    async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<FolderCreate<Self::Error>> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let passphrase = self.user()?.generate_folder_password()?;
        let key: AccessKey = passphrase.into();

        let (buffer, _, summary, account_event) = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.create_folder(name, Some(key.clone())).await?
        };

        // Must save the password before getting the secure access key
        self.user_mut()?
            .save_folder_password(summary.id(), key)
            .await?;

        let options = AccessOptions {
            folder: Some(summary),
            ..Default::default()
        };

        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        let event =
            Event::Folder(account_event, WriteEvent::CreateVault(buffer));
        Ok(FolderCreate {
            folder,
            event,
            commit_state,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::Error>> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options).await?;

        // Update the provider
        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.rename_folder(&summary, &name).await?
        };

        Ok(FolderChange {
            event,
            commit_state,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::Error>> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::Error>> {
        let span = span!(Level::DEBUG, "import_folder");
        let _enter = span.enter();

        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let mut vault: Vault = decode(buffer.as_ref()).await?;

        // Need to verify permission to access the data
        vault.verify(&key).await?;

        tracing::debug!(id = %vault.id(), name = %vault.name());

        // Check for existing identifier
        //let vaults = Self::list_local_folders(&self.paths, false).await?;
        let existing_id = self.find(|s| s.id() == vault.summary().id()).await;

        let default_vault = self.default_folder().await;

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            tracing::debug!("rotate identifier");
            vault.rotate_identifier();
            true
        } else {
            false
        };

        let existing_name =
            self.find(|s| s.name() == vault.summary().name()).await;

        let has_name_changed = if existing_name.is_some() && !overwrite {
            let name = format!(
                "{} ({})",
                vault.summary().name(),
                vault.summary().id()
            );
            tracing::debug!("change folder name");
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
            tracing::debug!("remove default flag");
            vault.set_default_flag(false);
        }

        let buffer: Cow<[u8]> =
            if has_id_changed || has_name_changed || remove_default_flag {
                // Need to update the buffer as we changed the data
                Cow::Owned(encode(&vault).await?)
            } else {
                Cow::Borrowed(buffer.as_ref())
            };

        // Import the vault
        let (event, summary) = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer
                .import_folder(buffer.as_ref(), Some(&key), true)
                .await?
        };

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            self.user_mut()?
                .remove_folder_password(summary.id())
                .await?;
        }

        self.user_mut()?
            .save_folder_password(summary.id(), key)
            .await?;

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            {
                let storage = self.storage().await?;
                let mut writer = storage.write().await;
                let is_current =
                    if let Some(current) = writer.current_folder() {
                        current.id() == summary.id()
                    } else {
                        false
                    };

                if is_current {
                    writer.close_folder();
                }
            }
        }

        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options).await?;

        Ok(FolderCreate {
            folder: summary,
            event,
            commit_state,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let event = self.import_identity_vault(vault).await?;
        let event_log = self.account_log().await?;
        let mut event_log = event_log.write().await;
        event_log.apply(vec![&event]).await?;
        Ok(event)
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let buffer = self
            .export_folder_buffer(summary, new_key, save_key)
            .await?;
        vfs::write(path, buffer).await?;
        Ok(())
    }

    async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let buffer = self
            .change_vault_password(summary.id(), new_key.clone())
            .await?;

        if save_key {
            let default_summary = self
                .default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?;

            let _passphrase = self
                .user()?
                .find_folder_password(default_summary.id())
                .await?;

            let timestamp: UtcDateTime = Default::default();
            let label = format!(
                "Exported folder {}.vault ({})",
                summary.id(),
                timestamp.to_rfc3339()?
            );
            let secret = Secret::Account {
                account: format!("{}.vault", summary.id()),
                url: None,
                password: new_key.into(),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());

            let (vault, _) =
                Identity::load_local_vault(&self.paths, default_summary.id())
                    .await?;

            self.add_secret(
                meta,
                secret,
                vault.summary().clone().into(),
                false,
            )
            .await?;
        }

        let audit_event = AuditEvent::new(
            EventKind::ExportVault,
            *self.address(),
            Some(AuditData::Vault(*summary.id())),
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(buffer)
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<FolderDelete<Self::Error>> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options).await?;

        let events = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.delete_folder(&summary, true).await?
        };
        self.user_mut()?
            .remove_folder_password(summary.id())
            .await?;

        Ok(FolderDelete {
            events,
            commit_state,
            #[cfg(feature = "sync")]
            sync_error: None,
            marker: std::marker::PhantomData,
        })
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let (data, _) = self.read_secret(secret_id, folder).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let jpeg = if let Ok(mut jpegs) = vcard.parse_photo_jpeg() {
                if !jpegs.is_empty() {
                    Some(jpegs.remove(0))
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(jpeg);
        }
        Ok(None)
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let current_folder = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            folder
                .clone()
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?
        };

        let (data, _) = self.get_secret(secret_id, folder, false).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let content = vcard.to_string();
            vfs::write(&path, content).await?;
        } else {
            return Err(Error::NotContact);
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ExportContacts,
                self.address().clone(),
                Some(AuditData::Secret(*current_folder.id(), *secret_id)),
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;

        let contacts_passphrase =
            self.user()?.find_folder_password(contacts.id()).await?;
        let (vault, _) =
            Identity::load_local_vault(&self.paths, contacts.id()).await?;
        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = contacts_passphrase.into();
        keeper.unlock(&key).await?;

        let mut vcf = String::new();
        let keys: Vec<&SecretId> = keeper.vault().keys().collect();
        for key in keys {
            if let Some((_, Secret::Contact { vcard, .. }, _)) =
                keeper.read_secret(key).await?
            {
                vcf.push_str(&vcard.to_string());
            }
        }
        vfs::write(path, vcf.as_bytes()).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ExportContacts,
                self.address().clone(),
                None,
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> Result<Vec<SecretId>> {
        use crate::vcard4::parse;

        let mut ids = Vec::new();
        let current = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            reader.current_folder()
        };

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;
        self.open_vault(&contacts, false).await?;

        let cards = parse(content)?;

        progress(ContactImportProgress::Ready { total: cards.len() });

        for (index, vcard) in cards.into_iter().enumerate() {
            let label = vcard
                .formatted_name
                .get(0)
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let secret = Secret::Contact {
                vcard: Box::new(vcard),
                user_data: Default::default(),
            };

            progress(ContactImportProgress::Item {
                label: label.clone(),
                index,
            });

            let meta = SecretMeta::new(label, secret.kind());
            let result =
                self.create_secret(meta, secret, Default::default()).await?;
            ids.push(result.id);
        }

        if let Some(folder) = current {
            self.open_vault(&folder, false).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ImportContacts,
                self.address().clone(),
                None,
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(ids)
    }

    /// Generate a security report.
    #[cfg(feature = "security-report")]
    async fn generate_security_report<T, D, R>(
        &mut self,
        options: SecurityReportOptions<T, D, R>,
    ) -> Result<SecurityReport<T>>
    where
        D: Fn(Vec<String>) -> R + Send + Sync,
        R: std::future::Future<Output = Vec<T>> + Send + Sync,
    {
        let mut records = Vec::new();
        let mut hashes = Vec::new();
        let folders = self.list_folders().await?;
        let targets: Vec<Summary> = folders
            .into_iter()
            .filter(|folder| {
                if let Some(target) = &options.target {
                    return folder.id() == &target.0;
                }
                !options.excludes.contains(folder.id())
            })
            .collect();

        for target in targets {
            let storage = self.storage().await?;
            let reader = storage.read().await;

            let folder = reader.cache().get(target.id()).unwrap();
            let keeper = folder.keeper();

            let vault = keeper.vault();
            let mut password_hashes: Vec<(
                SecretId,
                (Option<Entropy>, Vec<u8>),
                Option<SecretId>,
            )> = Vec::new();

            if let Some(target) = &options.target {
                secret_security_report(
                    &target.1,
                    keeper,
                    &mut password_hashes,
                    target.2.as_ref(),
                )
                .await?;
            } else {
                for secret_id in vault.keys() {
                    secret_security_report(
                        secret_id,
                        keeper,
                        &mut password_hashes,
                        None,
                    )
                    .await?;
                }
            }

            for (secret_id, check, field_id) in password_hashes {
                let (entropy, sha1) = check;

                let record = SecurityReportRecord {
                    folder: target.clone(),
                    secret_id,
                    field_id,
                    entropy,
                };

                hashes.push(hex::encode(sha1));
                records.push(record);
            }
        }

        let database_checks =
            if let Some(database_handler) = options.database_handler {
                (database_handler)(hashes).await
            } else {
                vec![]
            };
        Ok(SecurityReport {
            records,
            database_checks,
        })
    }

    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> crate::Result<()> {
        use std::io::Cursor;

        let paths = self.paths();
        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = Identity::list_local_folders(&paths).await?;

        for (summary, _) in vaults {
            let (vault, _) =
                Identity::load_local_vault(&*paths, summary.id())
                    .await
                    .map_err(Box::from)?;
            let vault_passphrase =
                self.user()?.find_folder_password(summary.id()).await?;

            let mut keeper = Gatekeeper::new(vault);
            keeper.unlock(&vault_passphrase).await?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper).await?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer = serde_json::to_vec_pretty(self.user()?.account()?)?;
        // FIXME: constant for file name
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files).await?;
        migration.finish().await?;

        vfs::write(path.as_ref(), &archive).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ExportUnsafe,
                self.address().clone(),
                None,
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<FolderCreate<Error>> {
        let result = match target.format {
            ImportFormat::OnePasswordCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    OnePasswordCsv,
                )
                .await?
            }
            ImportFormat::DashlaneZip => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    DashlaneCsvZip,
                )
                .await?
            }
            ImportFormat::BitwardenCsv => {
                self.import_csv(target.path, target.folder_name, BitwardenCsv)
                    .await?
            }
            ImportFormat::ChromeCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    ChromePasswordCsv,
                )
                .await?
            }
            ImportFormat::FirefoxCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    FirefoxPasswordCsv,
                )
                .await?
            }
            ImportFormat::MacosCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    MacPasswordCsv,
                )
                .await?
            }
        };

        Ok(result)
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        use super::archive::AccountBackup;

        AccountBackup::export_archive_file(path, self.address(), &self.paths)
            .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ExportBackupArchive,
                *self.address(),
                None,
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "archive")]
    async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        use super::archive::AccountBackup;

        let mut inventory =
            AccountBackup::restore_archive_inventory(BufReader::new(buffer))
                .await?;
        let accounts = Identity::list_accounts(None).await?;
        let exists_local = accounts
            .iter()
            .any(|account| account.address() == &inventory.manifest.address);
        inventory.exists_local = exists_local;
        Ok(inventory)
    }

    /// Restore from a backup archive file.
    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let file = vfs::File::open(path).await?;
        let account =
            Self::import_archive_reader(file, options, data_dir.clone())
                .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ImportBackupArchive,
                *account.address(),
                None,
            );

            let data_dir = if let Some(data_dir) = &data_dir {
                data_dir.clone()
            } else {
                Paths::data_dir()?
            };
            let paths = Paths::new(data_dir, account.address().to_string());
            paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(account)
    }

    /// Restore from a backup archive file.
    #[cfg(feature = "archive")]
    async fn restore_backup_archive(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        password: SecretString,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        use super::archive::{AccountBackup, ExtractFilesLocation};

        let current_folder = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            reader.current_folder()
        };

        let files_dir =
            ExtractFilesLocation::Path(self.paths().files_dir().clone());

        options.files_dir = Some(files_dir);

        let reader = vfs::File::open(path).await?;
        let (targets, account) = AccountBackup::restore_archive_reader(
            BufReader::new(reader),
            options,
            password,
            data_dir,
        )
        .await?;

        {
            let keys = self.folder_keys().await?;
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.restore_archive(&targets, &keys).await?;
        }

        #[cfg(feature = "search")]
        self.build_search_index().await?;

        if let Some(folder) = &current_folder {
            // Note that we don't want the additional
            // audit event here
            self.open_vault(folder, false).await?;
        }

        let audit_event = AuditEvent::new(
            EventKind::ImportBackupArchive,
            *self.address(),
            None,
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(account)
    }
}
