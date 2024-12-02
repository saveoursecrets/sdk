//! Linked account supports syncing accounts on the
//! same device using a local client.
use crate::{
    AutoMerge, Error, Origin, RemoteResult, RemoteSync, RemoteSyncHandler,
    Result, SyncClient, SyncOptions, UpdateSet,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_sdk::{
    prelude::{
        AccessKey, AccessOptions, Account, AccountChange, AccountData,
        AccountEvent, Address, Cipher, CipherComparison, ClientStorage,
        CommitHash, CommitState, DetachedView, DeviceManager,
        DevicePublicKey, DeviceSigner, EventRecord, FolderChange,
        FolderCreate, FolderDelete, KeyDerivation, LocalAccount,
        NewFolderOptions, Paths, PublicIdentity, ReadEvent, Secret,
        SecretChange, SecretDelete, SecretId, SecretInsert, SecretMeta,
        SecretMove, SecretRow, SigninOptions, Summary, TrustedDevice, Vault,
        VaultCommit, VaultFlags, VaultId,
    },
    secrecy::SecretString,
    signer::ecdsa::BoxedEcdsaSigner,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

use super::local_client::LocalClient;

#[cfg(feature = "search")]
use crate::sdk::prelude::{
    AccountStatistics, ArchiveFilter, Document, DocumentCount, DocumentView,
    QueryFilter, SearchIndex,
};

#[cfg(feature = "archive")]
use crate::sdk::prelude::{Inventory, RestoreOptions};

#[cfg(feature = "contacts")]
use crate::sdk::prelude::ContactImportProgress;

#[cfg(feature = "archive")]
use tokio::io::{AsyncRead, AsyncSeek};

#[cfg(feature = "migrate")]
use crate::sdk::prelude::ImportTarget;

#[cfg(feature = "files")]
use crate::transfer::FileTransferQueueSender;

/// Linked account.
pub struct LinkedAccount {
    account: Arc<Mutex<LocalAccount>>,
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
        let account =
            LocalAccount::new_unauthenticated(address, data_dir).await?;
        Ok(Self {
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
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
        let account =
            LocalAccount::new_account(account_name, passphrase, data_dir)
                .await?;
        Ok(Self {
            address: *account.address(),
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
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
        let account = self.account.lock().await;
        account.is_authenticated().await
    }

    async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        let account = self.account.lock().await;
        Ok(account.account_signer().await?)
    }

    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        let mut account = self.account.lock().await;
        Ok(account.new_device_vault().await?)
    }

    async fn device_signer(&self) -> Result<DeviceSigner> {
        let account = self.account.lock().await;
        Ok(account.device_signer().await?)
    }

    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        let account = self.account.lock().await;
        Ok(account.device_public_key().await?)
    }

    async fn current_device(&self) -> Result<TrustedDevice> {
        let account = self.account.lock().await;
        Ok(account.current_device().await?)
    }

    async fn trusted_devices(&self) -> Result<IndexSet<TrustedDevice>> {
        let account = self.account.lock().await;
        Ok(account.trusted_devices().await?)
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        let account = self.account.lock().await;
        Ok(account.public_identity().await?)
    }

    async fn account_label(&self) -> Result<String> {
        let account = self.account.lock().await;
        Ok(account.account_label().await?)
    }

    async fn folder_description(
        &mut self,
        folder: &Summary,
    ) -> Result<String> {
        let mut account = self.account.lock().await;
        Ok(account.folder_description(folder).await?)
    }

    async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.set_folder_description(folder, description).await?)
    }

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let account = self.account.lock().await;
        Ok(account.find_folder_password(folder_id).await?)
    }

    async fn generate_folder_password(&self) -> Result<SecretString> {
        let account = self.account.lock().await;
        Ok(account.generate_folder_password().await?)
    }

    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let account = self.account.lock().await;
        Ok(account.identity_vault_buffer().await?)
    }

    async fn identity_folder_summary(&self) -> Result<Summary> {
        let account = self.account.lock().await;
        Ok(account.identity_folder_summary().await?)
    }

    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherComparison> {
        let mut account = self.account.lock().await;
        Ok(account.change_cipher(account_key, cipher, kdf).await?)
    }

    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.change_account_password(password).await?)
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let mut account = self.account.lock().await;
        Ok(account.sign_in(key).await?)
    }

    async fn sign_in_with_options(
        &mut self,
        key: &AccessKey,
        options: SigninOptions,
    ) -> Result<Vec<Summary>> {
        let mut account = self.account.lock().await;
        Ok(account.sign_in_with_options(key, options).await?)
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        let account = self.account.lock().await;
        account.verify(key).await
    }

    async fn open_folder(&self, summary: &Summary) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.open_folder(summary).await?)
    }

    async fn current_folder(&self) -> Result<Option<Summary>> {
        let account = self.account.lock().await;
        Ok(account.current_folder().await?)
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        let account = self.account.lock().await;
        account.find(predicate).await
    }

    async fn sign_out(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.sign_out().await?)
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.rename_account(account_name).await?)
    }

    async fn delete_account(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.delete_account().await?)
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        let account = self.account.lock().await;
        Ok(account.storage().await?)
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        let account = self.account.lock().await;
        Ok(account.secret_ids(summary).await?)
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        let mut account = self.account.lock().await;
        Ok(account.load_folders().await?)
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        let account = self.account.lock().await;
        Ok(account.list_folders().await?)
    }

    async fn account_data(&self) -> Result<AccountData> {
        let account = self.account.lock().await;
        Ok(account.account_data().await?)
    }

    async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let account = self.account.lock().await;
        Ok(account.root_commit(summary).await?)
    }

    async fn identity_state(&self) -> Result<CommitState> {
        let account = self.account.lock().await;
        Ok(account.identity_state().await?)
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let account = self.account.lock().await;
        Ok(account.commit_state(summary).await?)
    }

    async fn compact_account(
        &mut self,
    ) -> Result<HashMap<Summary, (AccountEvent, u64, u64)>> {
        let mut account = self.account.lock().await;
        Ok(account.compact_account().await?)
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<(AccountEvent, u64, u64)> {
        let mut account = self.account.lock().await;
        Ok(account.compact_folder(summary).await?)
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<Summary> {
        let mut account = self.account.lock().await;
        Ok(account.restore_folder(folder_id, records).await?)
    }

    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.change_folder_password(folder, new_key).await?)
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let account = self.account.lock().await;
        Ok(account.detached_view(summary, commit).await?)
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let mut account = self.account.lock().await;
        Ok(account.initialize_search_index().await?)
    }

    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        let account = self.account.lock().await;
        account.statistics().await
    }

    #[cfg(feature = "search")]
    async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let account = self.account.lock().await;
        Ok(account.index().await?)
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let account = self.account.lock().await;
        Ok(account.query_view(views, archive).await?)
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let account = self.account.lock().await;
        Ok(account.query_map(query, filter).await?)
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        let account = self.account.lock().await;
        Ok(account.document_count().await?)
    }

    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        let account = self.account.lock().await;
        Ok(account.document_exists(vault_id, label, id).await?)
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let account = self.account.lock().await;
        Ok(account
            .download_file(vault_id, secret_id, file_name)
            .await?)
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.create_secret(meta, secret, options).await?)
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.insert_secrets(secrets).await?)
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account
            .update_secret(secret_id, meta, secret, options, destination)
            .await?)
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.move_secret(secret_id, from, to, options).await?)
    }

    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        let account = self.account.lock().await;
        Ok(account.read_secret(secret_id, folder).await?)
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<(Option<VaultCommit>, ReadEvent)> {
        let account = self.account.lock().await;
        Ok(account.raw_secret(folder_id, secret_id).await?)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.delete_secret(secret_id, options).await?)
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.archive(from, secret_id, options).await?)
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        let mut account = self.account.lock().await;
        Ok(account.unarchive(secret_id, secret_meta, options).await?)
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
        let mut account = self.account.lock().await;
        Ok(account
            .update_file(secret_id, meta, path, options, destination)
            .await?)
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.create_folder(name, options).await?)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.rename_folder(summary, name).await?)
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.update_folder_flags(summary, flags).await?)
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.import_folder(path, key, overwrite).await?)
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.import_folder_buffer(buffer, key, overwrite).await?)
    }

    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let mut account = self.account.lock().await;
        Ok(account.import_identity_folder(vault).await?)
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account
            .export_folder(path, summary, new_key, save_key)
            .await?)
    }

    async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        let mut account = self.account.lock().await;
        Ok(account
            .export_folder_buffer(summary, new_key, save_key)
            .await?)
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<FolderDelete<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.delete_folder(summary).await?)
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let account = self.account.lock().await;
        Ok(account.load_avatar(secret_id, folder).await?)
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_contact(path, secret_id, folder).await?)
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_all_contacts(path).await?)
    }

    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> Result<Vec<SecretId>> {
        let mut account = self.account.lock().await;
        Ok(account.import_contacts(content, progress).await?)
    }

    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_unsafe_archive(path).await?)
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let mut account = self.account.lock().await;
        Ok(account.import_file(target).await?)
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_backup_archive(path).await?)
    }

    #[cfg(feature = "archive")]
    async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        Ok(Self::restore_archive_inventory(buffer).await?)
    }

    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        Ok(Self::import_backup_archive(path, options, data_dir).await?)
    }

    #[cfg(feature = "archive")]
    async fn restore_backup_archive(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        password: SecretString,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let mut account = self.account.lock().await;
        Ok(account
            .restore_backup_archive(path, password, options, data_dir)
            .await?)
    }
}

#[async_trait]
impl RemoteSyncHandler for LinkedAccount {
    type Client = LocalClient;
    type Account = LocalAccount;
    type Error = Error;

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn origin(&self) -> &Origin {
        self.client.origin()
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn account(&self) -> Arc<Mutex<Self::Account>> {
        self.account.clone()
    }

    #[cfg(feature = "files")]
    fn file_transfer_queue(&self) -> &FileTransferQueueSender {
        unimplemented!();
    }

    #[cfg(feature = "files")]
    async fn execute_sync_file_transfers(&self) -> Result<()> {
        unimplemented!();
    }
}

#[async_trait]
impl AutoMerge for LinkedAccount {}

#[async_trait]
impl RemoteSync for LinkedAccount {
    type Error = Error;

    async fn sync(&self) -> RemoteResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error> {
        todo!();
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        todo!();
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error> {
        unimplemented!(
            "sync file transfers not supported for linked accounts"
        );
    }
}
