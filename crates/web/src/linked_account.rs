//! Linked account supports syncing with a single remote.
use crate::{Error, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use secrecy::SecretString;
use sos_account::{
    Account, AccountChange, AccountData, CipherComparison, DetachedView,
    FolderChange, FolderCreate, FolderDelete, LocalAccount, SecretChange,
    SecretDelete, SecretInsert, SecretMove,
};
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, Folder, FolderEventLog,
};
use sos_client_storage::{AccessOptions, NewFolderOptions};
use sos_core::{
    AccountId, Origin, SecretId, VaultId,
    commit::{CommitHash, CommitState, Comparison},
    events::{
        WriteEvent,
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
    },
};
use sos_core::{
    FolderRef, Paths, PublicIdentity, UtcDateTime, VaultCommit, VaultFlags,
    crypto::{AccessKey, Cipher, KeyDerivation},
    device::{DevicePublicKey, TrustedDevice},
    events::{AccountEvent, DeviceEvent, EventRecord, ReadEvent},
};
use sos_login::{
    DelegatedAccess,
    device::{DeviceManager, DeviceSigner},
};
use sos_protocol::{
    RemoteResult, RemoteSync, SyncClient, SyncOptions,
    network_client::HttpClient,
};
use sos_remote_sync::{AutoMerge, RemoteSyncHandler};
use sos_sync::{
    CreateSet, ForceMerge, Merge, MergeOutcome, StorageEventLogs,
    SyncDirection, SyncStatus, SyncStorage, UpdateSet,
};
use sos_vault::{
    Summary, Vault,
    secret::{Secret, SecretMeta, SecretRow, SecretType},
};
use sos_vfs as vfs;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "clipboard")]
use {
    sos_account::{ClipboardCopyRequest, xclipboard::Clipboard},
    sos_core::SecretPath,
};

#[cfg(feature = "search")]
use sos_search::{
    AccountStatistics, ArchiveFilter, Document, DocumentCount, DocumentView,
    QueryFilter, SearchIndex,
};

#[cfg(feature = "contacts")]
use sos_account::ContactImportProgress;

#[cfg(feature = "migrate")]
use sos_migrate::import::ImportTarget;

#[cfg(feature = "files")]
use {
    sos_backend::FileEventLog, sos_core::events::patch::FileDiff,
    sos_protocol::transfer::FileTransferQueueSender,
};

/// Linked account syncs with a local account on the same device.
pub struct LinkedAccount {
    account: Arc<Mutex<LocalAccount>>,
    account_id: AccountId,
    paths: Arc<Paths>,
    client: HttpClient,
    /// Lock to prevent write to local storage
    /// whilst a sync operation is in progress.
    sync_lock: Arc<Mutex<()>>,
}

impl LinkedAccount {
    /// Create a new unauthenticated linked account.
    pub async fn new_unauthenticated(
        account_id: AccountId,
        target: BackendTarget,
        client: HttpClient,
    ) -> Result<Self> {
        let account =
            LocalAccount::new_unauthenticated(account_id, target).await?;
        Ok(Self {
            account_id,
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            client,
            sync_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Create a new linked account.
    pub async fn new_account(
        account_name: String,
        passphrase: SecretString,
        target: BackendTarget,
        client: HttpClient,
    ) -> Result<Self> {
        let account =
            LocalAccount::new_account(account_name, passphrase, target)
                .await?;
        Ok(Self {
            account_id: *account.account_id(),
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            client,
            sync_lock: Arc::new(Mutex::new(())),
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Account for LinkedAccount {
    type Error = Error;
    type NetworkResult = RemoteResult<Self::Error>;

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    async fn backend_target(&self) -> BackendTarget {
        let account = self.account.lock().await;
        account.backend_target().await
    }

    async fn folder(&self, folder_id: &VaultId) -> Result<Folder> {
        let account = self.account.lock().await;
        Ok(account.folder(folder_id).await?)
    }

    async fn is_authenticated(&self) -> bool {
        let account = self.account.lock().await;
        account.is_authenticated().await
    }

    async fn import_account_events(
        &mut self,
        events: CreateSet,
    ) -> Result<()> {
        let mut inner = self.account.lock().await;
        Ok(inner.import_account_events(events).await?)
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

    async fn patch_devices_unchecked(
        &mut self,
        events: &[DeviceEvent],
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.patch_devices_unchecked(events).await?)
    }

    async fn revoke_device(
        &mut self,
        device_key: &DevicePublicKey,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.revoke_device(device_key).await?)
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

    async fn account_name(&self) -> Result<String> {
        let account = self.account.lock().await;
        Ok(account.account_name().await?)
    }

    async fn folder_description(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<String> {
        let mut account = self.account.lock().await;
        Ok(account.folder_description(folder_id).await?)
    }

    async fn set_folder_description(
        &mut self,
        folder_id: &VaultId,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account
                .set_folder_description(folder_id, description)
                .await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn login_folder_summary(&self) -> Result<Summary> {
        let account = self.account.lock().await;
        Ok(account.login_folder_summary().await?)
    }

    async fn reload_login_folder(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.reload_login_folder().await?)
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

    async fn verify(&self, key: &AccessKey) -> bool {
        let account = self.account.lock().await;
        account.verify(key).await
    }

    async fn open_folder(&self, folder_id: &VaultId) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.open_folder(folder_id).await?)
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

    async fn find_folder(&self, vault: &FolderRef) -> Option<Summary> {
        let account = self.account.lock().await;
        account.find_folder(vault).await
    }

    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let account = self.account.lock().await;
        Ok(account.history(folder_id).await?)
    }

    async fn sign_out(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.sign_out().await?)
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.rename_account(account_name).await?
        };

        let result = AccountChange {
            event: result.event,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn set_account_name(
        &mut self,
        account_name: String,
    ) -> std::result::Result<(), Self::Error> {
        let mut account = self.account.lock().await;
        Ok(account.set_account_name(account_name).await?)
    }

    async fn delete_account(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.delete_account().await?)
    }

    async fn list_secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<SecretId>> {
        let account = self.account.lock().await;
        Ok(account.list_secret_ids(folder_id).await?)
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

    async fn root_hash(&self, folder_id: &VaultId) -> Result<CommitHash> {
        let account = self.account.lock().await;
        Ok(account.root_hash(folder_id).await?)
    }

    async fn identity_state(&self) -> Result<CommitState> {
        let account = self.account.lock().await;
        Ok(account.identity_state().await?)
    }

    async fn commit_state(&self, folder_id: &VaultId) -> Result<CommitState> {
        let account = self.account.lock().await;
        Ok(account.commit_state(folder_id).await?)
    }

    async fn compact_account(
        &mut self,
    ) -> Result<HashMap<Summary, AccountEvent>> {
        let mut account = self.account.lock().await;
        Ok(account.compact_account().await?)
    }

    async fn compact_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<AccountEvent> {
        let mut account = self.account.lock().await;
        Ok(account.compact_folder(folder_id).await?)
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
        folder_id: &VaultId,
        new_key: AccessKey,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.change_folder_password(folder_id, new_key).await?)
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        folder_id: &VaultId,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let account = self.account.lock().await;
        Ok(account.detached_view(folder_id, commit).await?)
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
    async fn search_index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let account = self.account.lock().await;
        Ok(account.search_index().await?)
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
        file_name: &sos_core::ExternalFileName,
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
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.create_secret(meta, secret, options).await?
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.insert_secrets(secrets).await?
        };

        #[cfg(feature = "files")]
        let mut file_events = Vec::new();

        let result = SecretInsert {
            results: result
                .results
                .into_iter()
                .map(|#[allow(unused_mut)] mut result| {
                    #[cfg(feature = "files")]
                    file_events.append(&mut result.file_events);
                    SecretChange {
                        id: result.id,
                        event: result.event,
                        commit_state: result.commit_state,
                        folder: result.folder,
                        sync_result: RemoteResult {
                            origin: self.client.origin().clone(),
                            result: Ok(None),
                        },
                        #[cfg(feature = "files")]
                        file_events: result.file_events,
                    }
                })
                .collect(),
            sync_result: self.sync().await,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&file_events).await?;
        */

        Ok(result)
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account
                .update_secret(secret_id, meta, secret, options)
                .await?
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &VaultId,
        to: &VaultId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.move_secret(secret_id, from, to, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> Result<(SecretRow, ReadEvent)> {
        let account = self.account.lock().await;
        Ok(account.read_secret(secret_id, folder).await?)
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(VaultCommit, ReadEvent)>> {
        let account = self.account.lock().await;
        Ok(account.raw_secret(folder_id, secret_id).await?)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.delete_secret(secret_id, options).await?
        };

        let result = SecretDelete {
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn archive(
        &mut self,
        folder_id: &VaultId,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.archive(folder_id, secret_id, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_kind: &SecretType,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        let _ = self.sync_lock.lock().await;

        let (result, to) = {
            let mut account = self.account.lock().await;
            account.unarchive(secret_id, secret_kind, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok((result, to))
    }

    #[cfg(feature = "files")]
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.update_file(secret_id, meta, path, options).await?
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        /*
        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;
        */

        Ok(result)
    }

    async fn create_folder(
        &mut self,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.create_folder(options).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn create_shared_folder(
        &mut self,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.create_shared_folder(options).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn rename_folder(
        &mut self,
        folder_id: &VaultId,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.rename_folder(folder_id, name).await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn update_folder_flags(
        &mut self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.update_folder_flags(folder_id, flags).await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.import_folder_buffer(buffer, key, overwrite).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn import_login_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let mut account = self.account.lock().await;
        Ok(account.import_login_folder(vault).await?)
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account
            .export_folder(path, folder_id, new_key, save_key)
            .await?)
    }

    async fn export_folder_buffer(
        &mut self,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        let mut account = self.account.lock().await;
        Ok(account
            .export_folder_buffer(folder_id, new_key, save_key)
            .await?)
    }

    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<FolderDelete<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.delete_folder(folder_id).await?
        };

        let result = FolderDelete {
            events: result.events,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
    }

    async fn forget_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        let mut account = self.account.lock().await;
        Ok(account.forget_folder(folder_id).await?)
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> Result<Option<Vec<u8>>> {
        let account = self.account.lock().await;
        Ok(account.load_avatar(secret_id, folder).await?)
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
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
        _path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        unimplemented!();
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        _target: ImportTarget,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        unimplemented!();
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        _path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        unimplemented!();
    }

    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        _path: impl AsRef<Path> + Send + Sync,
        _target: &BackendTarget,
    ) -> Result<Vec<PublicIdentity>> {
        unimplemented!();
    }

    #[cfg(feature = "clipboard")]
    async fn copy_clipboard(
        &self,
        _clipboard: &Clipboard,
        _target: &SecretPath,
        _request: &ClipboardCopyRequest,
    ) -> Result<bool> {
        unimplemented!();
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for LinkedAccount {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        let account = self.account.lock().await;
        Ok(account.identity_log().await?)
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        let account = self.account.lock().await;
        Ok(account.account_log().await?)
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        let account = self.account.lock().await;
        Ok(account.device_log().await?)
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        let account = self.account.lock().await;
        Ok(account.file_log().await?)
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let account = self.account.lock().await;
        Ok(account.folder_details().await?)
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let account = self.account.lock().await;
        Ok(account.folder_log(id).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncStorage for LinkedAccount {
    fn is_client_storage(&self) -> bool {
        true
    }

    async fn sync_status(&self) -> Result<SyncStatus> {
        let account = self.account.lock().await;
        Ok(account.sync_status().await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Merge for LinkedAccount {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_identity(diff, outcome).await?)
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_identity(state).await?)
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        let mut account = self.account.lock().await;
        Ok(account.merge_account(diff, outcome).await?)
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_account(state).await?)
    }

    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_device(diff, outcome).await?)
    }

    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_device(state).await?)
    }

    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_files(diff, outcome).await?)
    }

    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_files(state).await?)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let mut account = self.account.lock().await;
        Ok(account.merge_folder(folder_id, diff, outcome).await?)
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_folder(folder_id, state).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ForceMerge for LinkedAccount {
    async fn force_merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.force_merge_identity(diff, outcome).await?)
    }

    async fn force_merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.force_merge_account(diff, outcome).await?)
    }

    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.force_merge_device(diff, outcome).await?)
    }

    /// Force merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.force_merge_files(diff, outcome).await?)
    }

    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.force_merge_folder(folder_id, diff, outcome).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RemoteSyncHandler for LinkedAccount {
    type Client = HttpClient;
    type Account = LocalAccount;
    type Error = Error;

    fn direction(&self) -> SyncDirection {
        SyncDirection::Pull
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn origin(&self) -> &Origin {
        self.client.origin()
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AutoMerge for LinkedAccount {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RemoteSync for LinkedAccount {
    type Error = Error;

    async fn sync(&self) -> RemoteResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error> {
        match self.execute_sync(options).await {
            Ok(outcome) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(outcome),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        match self.client.update_account(account_data).await {
            Ok(_) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e.into()),
            },
        }
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error> {
        unimplemented!(
            "sync file transfers not supported for linked accounts"
        );
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DelegatedAccess for LinkedAccount {
    type Error = Error;

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let account = self.account.lock().await;
        Ok(account.find_folder_password(folder_id).await?)
    }

    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.remove_folder_password(folder_id).await?)
    }

    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.save_folder_password(folder_id, key).await?)
    }
}
