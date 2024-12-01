//! Linked account supports syncing accounts on the
//! same device using a local client.
use crate::{Origin, RemoteResult, RemoteSync, SyncOptions, UpdateSet};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_sdk::{
    prelude::*, secrecy::SecretString, signer::ecdsa::BoxedEcdsaSigner,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

use super::local_client::LocalClient;

/// Linked account.
pub struct LinkedAccount {
    inner: LocalAccount,
    client: LocalClient,
}

impl LinkedAccount {
    /// Create a new unauthenticated linked account.
    pub async fn new_unauthenticated(
        address: Address,
        client: LocalClient,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let inner =
            LocalAccount::new_unauthenticated(address, data_dir).await?;
        Ok(Self { inner, client })
    }

    /// Create a new linked account.
    pub async fn new_account(
        account_name: String,
        passphrase: SecretString,
        client: LocalClient,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let inner =
            LocalAccount::new_account(account_name, passphrase, data_dir)
                .await?;
        Ok(Self { inner, client })
    }
}

#[async_trait]
impl Account for LinkedAccount {
    type Error = Error;
    type NetworkResult = ();

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

    async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        self.inner.root_commit(summary).await
    }

    async fn identity_state(&self) -> Result<CommitState> {
        self.inner.identity_state().await
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        self.inner.commit_state(summary).await
    }

    async fn compact_account(
        &mut self,
    ) -> Result<HashMap<Summary, (AccountEvent, u64, u64)>> {
        self.inner.compact_account().await
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<(AccountEvent, u64, u64)> {
        self.inner.compact_folder(summary).await
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<Summary> {
        self.inner.restore_folder(folder_id, records).await
    }

    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        self.inner.change_folder_password(folder, new_key).await
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        self.inner.detached_view(summary, commit).await
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        self.inner.initialize_search_index().await
    }

    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        self.inner.statistics().await
    }

    #[cfg(feature = "search")]
    async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        self.inner.index().await
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        self.inner.query_view(views, archive).await
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        self.inner.query_map(query, filter).await
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        self.inner.document_count().await
    }

    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        self.inner.document_exists(vault_id, label, id).await
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        self.inner
            .download_file(vault_id, secret_id, file_name)
            .await
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        self.inner.create_secret(meta, secret, options).await
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::NetworkResult>> {
        self.inner.insert_secrets(secrets).await
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        self.inner
            .update_secret(secret_id, meta, secret, options, destination)
            .await
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        self.inner.move_secret(secret_id, from, to, options).await
    }

    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.inner.read_secret(secret_id, folder).await
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<(Option<VaultCommit>, ReadEvent)> {
        self.inner.raw_secret(folder_id, secret_id).await
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::NetworkResult>> {
        self.inner.delete_secret(secret_id, options).await
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        self.inner.archive(from, secret_id, options).await
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        self.inner.unarchive(secret_id, secret_meta, options).await
    }

    #[cfg(feature = "files")]
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        self.inner
            .update_file(secret_id, meta, path, options, destination)
            .await
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.inner.create_folder(name, options).await
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.inner.rename_folder(summary, name).await
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.inner.update_folder_flags(summary, flags).await
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.inner.import_folder(path, key, overwrite).await
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.inner
            .import_folder_buffer(buffer, key, overwrite)
            .await
    }

    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        self.inner.import_identity_folder(vault).await
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        self.inner
            .export_folder(path, summary, new_key, save_key)
            .await
    }

    async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        self.inner
            .export_folder_buffer(summary, new_key, save_key)
            .await
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<FolderDelete<Self::NetworkResult>> {
        self.inner.delete_folder(summary).await
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        self.inner.load_avatar(secret_id, folder).await
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        self.inner.export_contact(path, secret_id, folder).await
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        self.inner.export_all_contacts(path).await
    }

    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> Result<Vec<SecretId>> {
        self.inner.import_contacts(content, progress).await
    }

    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        self.inner.export_unsafe_archive(path).await
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.inner.import_file(target).await
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        self.inner.export_backup_archive(path).await
    }

    #[cfg(feature = "archive")]
    async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        Self::restore_archive_inventory(buffer).await
    }

    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        Self::import_backup_archive(path, options, data_dir).await
    }

    #[cfg(feature = "archive")]
    async fn restore_backup_archive(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        password: SecretString,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        self.inner
            .restore_backup_archive(path, password, options, data_dir)
            .await
    }
}

#[async_trait]
impl RemoteSync for LinkedAccount {
    type Error = crate::Error;

    async fn sync(&self) -> RemoteResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error> {
        todo!();
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error> {
        unimplemented!(
            "sync file transfers not supported for linked accounts"
        );
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        todo!();
    }
}
