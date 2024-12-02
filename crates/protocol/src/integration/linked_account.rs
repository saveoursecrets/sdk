//! Linked account supports syncing accounts on the
//! same device using a local client.
use crate::{RemoteResult, RemoteSync, SyncOptions, UpdateSet};
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

#[cfg(feature = "archive")]
use tokio::io::{AsyncRead, AsyncSeek};

/// Linked account.
pub struct LinkedAccount {
    inner: Arc<RwLock<LocalAccount>>,
    address: Address,
    paths: Arc<Paths>,
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
        Ok(Self {
            paths: inner.paths(),
            inner: Arc::new(RwLock::new(inner)),
            address,
            client,
        })
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
        Ok(Self {
            address: *inner.address(),
            paths: inner.paths(),
            inner: Arc::new(RwLock::new(inner)),
            client,
        })
    }
}

#[async_trait]
impl Account for LinkedAccount {
    type Error = Error;
    type NetworkResult = ();

    fn address(&self) -> &Address {
        &self.address
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    async fn is_authenticated(&self) -> bool {
        let inner = self.inner.read().await;
        inner.is_authenticated()
    }

    async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        let inner = self.inner.read().await;
        inner.account_signer()
    }

    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        let mut inner = self.inner.write().await;
        inner.new_device_vault()
    }

    async fn device_signer(&self) -> Result<DeviceSigner> {
        let inner = self.inner.read().await;
        inner.device_signer()
    }

    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        let inner = self.inner.read().await;
        inner.device_public_key()
    }

    async fn current_device(&self) -> Result<TrustedDevice> {
        let inner = self.inner.read().await;
        inner.current_device()
    }

    async fn trusted_devices(&self) -> Result<IndexSet<TrustedDevice>> {
        let inner = self.inner.read().await;
        inner.trusted_devices()
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        let inner = self.inner.read().await;
        inner.public_identity()
    }

    async fn account_label(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.account_label()
    }

    async fn folder_description(
        &mut self,
        folder: &Summary,
    ) -> Result<String> {
        let mut inner = self.inner.write().await;
        inner.folder_description(folder)
    }

    async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.set_folder_description(folder, description)
    }

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let inner = self.inner.read().await;
        inner.find_folder_password(folder_id)
    }

    async fn generate_folder_password(&self) -> Result<SecretString> {
        let inner = self.inner.read().await;
        inner.generate_folder_password()
    }

    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let inner = self.inner.read().await;
        inner.identity_vault_buffer()
    }

    async fn identity_folder_summary(&self) -> Result<Summary> {
        let inner = self.inner.read().await;
        inner.identity_folder_summary()
    }

    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherComparison> {
        let mut inner = self.inner.write().await;
        inner.change_cipher(account_key, cipher, kdf)
    }

    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.change_account_password(password)
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let mut inner = self.inner.write().await;
        inner.sign_in(key).await
    }

    async fn sign_in_with_options(
        &mut self,
        key: &AccessKey,
        options: SigninOptions,
    ) -> Result<Vec<Summary>> {
        let mut inner = self.inner.write().await;
        inner.sign_in_with_options(key, options).await
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        let inner = self.inner.read().await;
        inner.verify(key).await
    }

    async fn open_folder(&self, summary: &Summary) -> Result<()> {
        let inner = self.inner.read().await;
        inner.open_folder(summary).await
    }

    async fn current_folder(&self) -> Result<Option<Summary>> {
        let inner = self.inner.read().await;
        inner.current_folder().await
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        let inner = self.inner.read().await;
        inner.find(predicate).await
    }

    async fn sign_out(&mut self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.sign_out().await
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.rename_account(account_name).await
    }

    async fn delete_account(&mut self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.delete_account().await
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        let inner = self.inner.read().await;
        inner.storage().await
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        let inner = self.inner.read().await;
        inner.secret_ids(summary).await
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        let mut inner = self.inner.write().await;
        inner.load_folders().await
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        let inner = self.inner.read().await;
        inner.list_folders().await
    }

    async fn account_data(&self) -> Result<AccountData> {
        let inner = self.inner.read().await;
        inner.account_data().await
    }

    async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let inner = self.inner.read().await;
        inner.root_commit(summary).await
    }

    async fn identity_state(&self) -> Result<CommitState> {
        let inner = self.inner.read().await;
        inner.identity_state().await
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let inner = self.inner.read().await;
        inner.commit_state(summary).await
    }

    async fn compact_account(
        &mut self,
    ) -> Result<HashMap<Summary, (AccountEvent, u64, u64)>> {
        let mut inner = self.inner.write().await;
        inner.compact_account().await
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<(AccountEvent, u64, u64)> {
        let mut inner = self.inner.write().await;
        inner.compact_folder(summary).await
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<Summary> {
        let mut inner = self.inner.write().await;
        inner.restore_folder(folder_id, records).await
    }

    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.change_folder_password(folder, new_key).await
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let inner = self.inner.read().await;
        inner.detached_view(summary, commit)
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let mut inner = self.inner.write().await;
        inner.initialize_search_index()
    }

    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        let inner = self.inner.read().await;
        inner.statistics()
    }

    #[cfg(feature = "search")]
    async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let inner = self.inner.read().await;
        inner.index()
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let inner = self.inner.read().await;
        inner.query_view(views, archive)
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let inner = self.inner.read().await;
        inner.query_map(query, filter)
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        let inner = self.inner.read().await;
        inner.document_count()
    }

    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        let inner = self.inner.read().await;
        inner.document_exists(vault_id, label, id)
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let inner = self.inner.read().await;
        inner.download_file(vault_id, secret_id, file_name)
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.create_secret(meta, secret, options)
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.insert_secrets(secrets)
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.update_secret(secret_id, meta, secret, options, destination)
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.move_secret(secret_id, from, to, options)
    }

    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        let inner = self.inner.read().await;
        inner.read_secret(secret_id, folder)
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<(Option<VaultCommit>, ReadEvent)> {
        let inner = self.inner.read().await;
        inner.raw_secret(folder_id, secret_id)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.delete_secret(secret_id, options)
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.archive(from, secret_id, options)
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        let mut inner = self.inner.write().await;
        inner.unarchive(secret_id, secret_meta, options)
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
        let mut inner = self.inner.write().await;
        inner.update_file(secret_id, meta, path, options, destination)
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.create_folder(name, options)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.rename_folder(summary, name)
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.update_folder_flags(summary, flags)
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.import_folder(path, key, overwrite)
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.import_folder_buffer(buffer, key, overwrite)
    }

    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let mut inner = self.inner.write().await;
        inner.import_identity_folder(vault)
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.export_folder(path, summary, new_key, save_key)
    }

    async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        let mut inner = self.inner.write().await;
        inner.export_folder_buffer(summary, new_key, save_key)
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<FolderDelete<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.delete_folder(summary)
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let inner = self.inner.read().await;
        inner.load_avatar(secret_id, folder)
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let inner = self.inner.read().await;
        inner.export_contact(path, secret_id, folder)
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let inner = self.inner.read().await;
        inner.export_all_contacts(path)
    }

    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> Result<Vec<SecretId>> {
        let mut inner = self.inner.write().await;
        inner.import_contacts(content, progress)
    }

    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let inner = self.inner.read().await;
        inner.export_unsafe_archive(path)
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut inner = self.inner.write().await;
        inner.import_file(target)
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let inner = self.inner.read().await;
        inner.export_backup_archive(path)
    }

    #[cfg(feature = "archive")]
    async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        Self::restore_archive_inventory(buffer)
    }

    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        Self::import_backup_archive(path, options, data_dir)
    }

    #[cfg(feature = "archive")]
    async fn restore_backup_archive(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        password: SecretString,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let mut inner = self.inner.write().await;
        inner.restore_backup_archive(path, password, options, data_dir)
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
