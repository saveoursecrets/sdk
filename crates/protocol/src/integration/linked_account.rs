//! Linked account supports syncing accounts on the
//! same device using a local client.
use crate::{
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet, WireEncodeDecode,
};
use async_trait::async_trait;
use http::StatusCode;
use sos_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::local_client::LocalClient;

/// Linked account.
pub struct LinkedAccount {
    inner: LocalAccount,
    client: LocalClient,
}

impl LinkedAccount {}

#[async_trait]
impl Account for LinkedAccount {
    type Error = Error;
    type NetworkResult = ();

    type NetworkResult: std::fmt::Debug;

    fn address(&self) -> &Address {
        self.inner.address()
    }

    fn paths(&self) -> Arc<Paths> {
        self.inner.paths()
    }

    async fn is_authenticated(&self) -> bool {
        self.inner.is_authenticated().await
    }

    async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        self.inner.account_signer().await
    }

    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        self.inner.new_device_vault().await
    }

    async fn device_signer(&self) -> Result<DeviceSigner> {
        self.inner.device_signer().await
    }

    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        self.inner.device_public_key().await
    }

    async fn current_device(&self) -> Result<TrustedDevice> {
        self.inner.current_device().await
    }

    async fn trusted_devices(&self) -> Result<IndexSet<TrustedDevice>> {
        self.inner.trusted_devices().await
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        self.inner.public_identity().await
    }

    async fn account_label(&self) -> Result<String> {
        self.inner.account_label().await
    }

    async fn folder_description(
        &mut self,
        folder: &Summary,
    ) -> Result<String> {
        self.inner.folder_description(folder).await
    }

    async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.inner.set_folder_description(folder, description).await
    }

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        self.inner.find_folder_password(folder_id).await
    }

    async fn generate_folder_password(&self) -> Result<SecretString> {
        self.inner.generate_folder_password().await
    }

    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        self.inner.identity_vault_buffer().await
    }

    async fn identity_folder_summary(&self) -> Result<Summary> {
        self.inner.identity_folder_summary().await
    }

    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherComparison> {
        self.inner.change_cipher(account_key, cipher, kdf).await
    }

    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> Result<()> {
        self.change_account_password(password).await
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        self.inner.sign_in(key).await
    }

    async fn sign_in_with_options(
        &mut self,
        key: &AccessKey,
        options: SigninOptions,
    ) -> Result<Vec<Summary>> {
        self.inner.sign_in_with_options(key, options).await
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        self.inner.verify(key).await
    }

    async fn open_folder(&self, summary: &Summary) -> Result<()> {
        self.inner.open_folder(summary).await
    }

    async fn current_folder(&self) -> Result<Option<Summary>> {
        self.inner.current_folder().await
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        self.inner.find(predicate).await
    }

    async fn sign_out(&mut self) -> Result<()> {
        self.inner.sign_out().await
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Self::NetworkResult>> {
        self.inner.rename_account(account_name).await
    }

    async fn delete_account(&mut self) -> Result<()> {
        self.inner.delete_account().await
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        self.inner.storage().await
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        self.inner.secret_ids(summary).await
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        self.inner.load_folders().await
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        self.inner.list_folders().await
    }

    async fn account_data(&self) -> Result<AccountData> {
        self.inner.account_data().await
    }

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

    /// Compact the identity folder and all user folders.
    async fn compact_account(
        &mut self,
    ) -> std::result::Result<
        HashMap<Summary, (AccountEvent, u64, u64)>,
        Self::Error,
    >;

    /// Compact the event log file for a folder.
    async fn compact_folder(
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<(AccountEvent, u64, u64), Self::Error>;

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
        folder: &Summary,
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
        summary: &Summary,
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
        destination: Option<&Summary>,
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
        folder: Option<Summary>,
    ) -> std::result::Result<(SecretRow, ReadEvent), Self::Error>;

    /// Read the encrypted contents of a secret.
    ///
    /// Does not affect the currently open folder and
    /// does not append any audit logs.
    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> std::result::Result<(Option<VaultCommit>, ReadEvent), Self::Error>;

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
        destination: Option<&Summary>,
    ) -> std::result::Result<SecretChange<Self::NetworkResult>, Self::Error>;

    /// Create a folder.
    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> std::result::Result<FolderCreate<Self::NetworkResult>, Self::Error>;

    /// Rename a folder.
    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> std::result::Result<FolderChange<Self::NetworkResult>, Self::Error>;

    /// Update folder flags.
    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
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
    ) -> std::result::Result<FolderDelete<Self::NetworkResult>, Self::Error>;

    /// Try to load an avatar JPEG image for a contact.
    ///
    /// Looks in the current open folder if no specified folder is given.
    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    /// Export a contact secret to a vCard file.
    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
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
        target: ImportTarget,
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
