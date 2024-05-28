//! Network aware account.
use async_trait::async_trait;
use secrecy::SecretString;
use sos_sdk::{
    account::{
        Account, AccountBuilder, AccountChange, AccountData,
        CipherComparison, DetachedView, FolderChange, FolderCreate,
        FolderDelete, LocalAccount, SecretChange, SecretDelete, SecretInsert,
        SecretMove, SigninOptions,
    },
    commit::{CommitHash, CommitState},
    crypto::{AccessKey, Cipher, KeyDerivation},
    events::{AccountEvent, EventLogExt, ReadEvent},
    identity::{AccountRef, PublicIdentity},
    sha2::{Digest, Sha256},
    signer::ecdsa::{Address, BoxedEcdsaSigner},
    storage::{
        files::{ExternalFile, FileMutationEvent, TransferOperation},
        search::{
            AccountStatistics, ArchiveFilter, Document, DocumentCount,
            DocumentView, QueryFilter, SearchIndex,
        },
        AccessOptions, ClientStorage, StorageEventLogs,
    },
    sync::{Origin, SyncOptions, UpdateSet},
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Summary, Vault, VaultId,
    },
    vfs, Paths,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncSeek},
    sync::{broadcast, Mutex, RwLock},
};

#[cfg(feature = "archive")]
use crate::sdk::account::archive::{Inventory, RestoreOptions};

#[cfg(feature = "device")]
use crate::sdk::device::{
    DeviceManager, DevicePublicKey, DeviceSigner, TrustedDevice,
};

#[cfg(feature = "device")]
use indexmap::IndexSet;

#[cfg(feature = "listen")]
use crate::client::WebSocketHandle;

#[cfg(feature = "contacts")]
use crate::sdk::account::ContactImportProgress;

#[cfg(feature = "security-report")]
use crate::sdk::account::security_report::{
    SecurityReport, SecurityReportOptions,
};

#[cfg(feature = "migrate")]
use crate::sdk::migrate::import::ImportTarget;

use super::{file_transfers::FileTransferSettings, remote::Remotes};
use crate::client::{Error, RemoteBridge, RemoteSync, Result};

#[cfg(feature = "files")]
use crate::{
    client::account::file_transfers::{
        FileTransfers, InflightTransfers, PendingOperations, TransfersQueue,
    },
    sdk::storage::files::FileTransfersSet,
};

/// Request to queue a file transfer.
#[cfg(feature = "files")]
#[derive(Debug, Clone)]
pub enum FileTransferQueueRequest {
    /// Add pending operations.
    Pending(PendingOperations),
    /// Merge file transfer set.
    MergeFileTransfers(FileTransfersSet),
}

/// Channel to add file transfers to the queue.
#[cfg(feature = "files")]
pub type FileTransferQueueChannel =
    broadcast::Sender<FileTransferQueueRequest>;

/// Options for network account creation.
#[derive(Debug, Default)]
pub struct NetworkAccountOptions {
    /// Disable network traffic.
    pub offline: bool,
    /// File transfer settings.
    #[cfg(feature = "files")]
    pub file_transfer_settings: FileTransferSettings,
}

/// Account with networking capability.
pub struct NetworkAccount {
    /// Address of this account.
    address: Address,

    /// Paths for the account.
    paths: Arc<Paths>,

    /// Local account.
    pub(super) account: Arc<Mutex<LocalAccount>>,

    /// Remote targets for synchronization.
    pub(super) remotes: Arc<RwLock<Remotes>>,

    /// Lock to prevent write to local storage
    /// whilst a sync operation is in progress.
    pub(super) sync_lock: Arc<Mutex<()>>,

    /// Websocket change listeners.
    #[cfg(feature = "listen")]
    pub(super) listeners: Mutex<HashMap<Origin, WebSocketHandle>>,

    /// Identifier for this client connection.
    ///
    /// When listening for changes use the same identifier
    /// so the server can filter out broadcast messages
    /// made by this client.
    connection_id: Option<String>,

    /// File transfer event loop.
    #[cfg(feature = "files")]
    file_transfers: Option<FileTransfers>,

    /// Channel for adding file transfers to the queue.
    #[cfg(feature = "files")]
    file_transfer_queue: FileTransferQueueChannel,

    /// Disable networking.
    pub(crate) offline: bool,

    /// Options for the network account.
    options: NetworkAccountOptions,
}

impl NetworkAccount {
    async fn login(
        &mut self,
        key: &AccessKey,
        options: SigninOptions,
    ) -> Result<Vec<Summary>> {
        let folders = {
            let mut account = self.account.lock().await;
            let folders = account.sign_in_with_options(key, options).await?;
            self.paths = account.paths();
            self.address = account.address().clone();
            folders
        };

        // Without an explicit connection id use the inferred
        // connection identifier
        if self.connection_id.is_none() {
            self.connection_id = self.client_connection_id().await.ok();
        }

        let file_transfers = FileTransfers::new(
            self.paths(),
            self.options.file_transfer_settings.clone(),
        )
        .await?;
        self.file_transfers = Some(file_transfers);

        // Load origins from disc and create remote definitions
        if let Some(origins) = self.load_servers().await? {
            let mut remotes: Remotes = Default::default();

            for origin in origins {
                let remote = self.remote_bridge(&origin).await?;
                remotes.insert(origin, remote);
            }

            self.remotes = Arc::new(RwLock::new(remotes));
            self.start_file_transfers().await?;
        }

        Ok(folders)
    }

    /// Revoke a device.
    #[cfg(feature = "device")]
    pub async fn revoke_device(
        &mut self,
        device_key: &crate::sdk::device::DevicePublicKey,
    ) -> Result<()> {
        let current_device = self.current_device().await?;
        if current_device.public_key() == device_key {
            return Err(Error::RevokeDeviceSelf);
        }

        // Update the local device event log
        {
            let account = self.account.lock().await;
            let storage = account.storage().await?;
            let mut storage = storage.write().await;
            storage.revoke_device(device_key).await?;
        }

        println!("Sending patch devices request...");

        // Send the device event logs to the remote servers
        if let Some(e) = self.patch_devices(&Default::default()).await {
            tracing::error!(error = ?e);
            return Err(Error::RevokeDeviceSync(e));
        }

        Ok(())
    }

    /// Set the connection identifier.
    pub fn set_connection_id(&mut self, value: Option<String>) {
        self.connection_id = value;
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_ref().map(|x| x.as_str())
    }

    /// Connection identifier either explicitly set
    /// or inferred by convention.
    ///
    /// The convention is to use an Sha256 hash of the path
    /// to the documents directory for the account and when
    /// the account is authenticated include the device signing
    /// public key in the computed hash.
    async fn client_connection_id(&self) -> Result<String> {
        Ok(if let Some(conn_id) = &self.connection_id {
            conn_id.to_owned()
        } else {
            let mut hasher = Sha256::new();
            let docs_dir = self.paths.documents_dir();
            let docs_path = docs_dir.to_string_lossy().into_owned();

            if !self.is_authenticated().await {
                hasher.update(docs_path.as_bytes());
            } else {
                #[cfg(feature = "device")]
                {
                    let device_signer = self.device_signer().await?;
                    let device_public_key = device_signer.public_key();

                    hasher.update(docs_path.as_bytes());
                    hasher.update(device_public_key.as_ref());
                }
            }

            let result = hasher.finalize();
            hex::encode(&result)
        })
    }

    /// Add a server.
    ///
    /// If a server with the given origin already exists it is
    /// overwritten.
    pub async fn add_server(&mut self, origin: Origin) -> Result<()> {
        let remote = self.remote_bridge(&origin).await?;
        {
            let mut remotes = self.remotes.write().await;
            remotes.insert(origin, remote);
            self.save_remotes(&*remotes).await?;
        }
        self.start_file_transfers().await
    }

    /// Remove a server.
    pub async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<Option<RemoteBridge>> {
        let remote = {
            let mut remotes = self.remotes.write().await;
            let remote = remotes.remove(origin);
            if remote.is_some() {
                self.save_remotes(&*remotes).await?;
            }
            remote
        };
        self.start_file_transfers().await?;
        Ok(remote)
    }

    /// Create a remote bridge between this account and the origin server.
    async fn remote_bridge(&self, origin: &Origin) -> Result<RemoteBridge> {
        let signer = self.account_signer().await?;
        let device = self.device_signer().await?;
        let conn_id = if let Some(conn_id) = &self.connection_id {
            conn_id.to_string()
        } else {
            self.client_connection_id().await?
        };
        let provider = RemoteBridge::new(
            Arc::clone(&self.account),
            origin.clone(),
            signer,
            device.into(),
            conn_id,
            #[cfg(feature = "files")]
            self.file_transfer_queue.clone(),
        )?;
        Ok(provider)
    }

    /// List the origin servers.
    ///
    /// Derived from the currently configuted in-memory remotes.
    pub async fn servers(&self) -> HashSet<Origin> {
        let remotes = self.remotes.read().await;
        remotes.keys().cloned().collect()
    }

    /// Load origin servers from disc.
    async fn load_servers(&self) -> Result<Option<HashSet<Origin>>> {
        let remotes_file = self.paths().remote_origins();
        if vfs::try_exists(&remotes_file).await? {
            let contents = vfs::read(&remotes_file).await?;
            let origins: HashSet<Origin> = serde_json::from_slice(&contents)?;
            Ok(Some(origins))
        } else {
            Ok(None)
        }
    }

    /// Save remote definitions to disc.
    async fn save_remotes(&self, remotes: &Remotes) -> Result<()> {
        let origins = remotes.keys().collect::<Vec<_>>();
        let data = serde_json::to_vec_pretty(&origins)?;
        let file = self.paths().remote_origins();
        vfs::write(file, data).await?;
        Ok(())
    }

    async fn before_change(&self) {
        if self.offline {
            tracing::warn!("offline mode active, ignoring before change");
        } else {
            let remotes = self.remotes.read().await;
            for remote in remotes.values() {
                if let Some(e) = remote.sync().await {
                    tracing::error!(error = ?e, "failed to sync before change");
                }
            }
        }
    }

    /// Spawn a task to handle file transfers.
    async fn start_file_transfers(&mut self) -> Result<()> {
        if !self.is_authenticated().await {
            return Err(crate::sdk::Error::NotAuthenticated.into());
        }

        if self.offline {
            tracing::warn!("offline mode active, ignoring file transfers");
            return Ok(());
        }

        // Stop any existing transfers task
        self.stop_file_transfers().await;

        if let Some(file_transfers) = &mut self.file_transfers {
            let clients = {
                let remotes = self.remotes.read().await;
                let mut clients = Vec::new();
                for (_, remote) in &*remotes {
                    clients.push(remote.client().clone());
                }
                clients
            };

            file_transfers.run(clients, self.file_transfer_queue.subscribe());
        }

        Ok(())
    }

    /// Stop a file transfers task.
    async fn stop_file_transfers(&mut self) {
        if let Some(mut file_transfers) = self.file_transfers.take() {
            file_transfers.stop().await;
        }
    }

    /// Close all the websocket connections
    #[cfg(feature = "listen")]
    async fn shutdown_listeners(&self) {
        let mut listeners = self.listeners.lock().await;
        for (_, handle) in listeners.drain() {
            tracing::debug!("close websocket");
            handle.close();
        }
    }
}

impl From<&NetworkAccount> for AccountRef {
    fn from(value: &NetworkAccount) -> Self {
        Self::Address(value.address().clone())
    }
}

impl NetworkAccount {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
        options: NetworkAccountOptions,
        // offline: bool,
    ) -> Result<Self> {
        let account =
            LocalAccount::new_unauthenticated(address, data_dir).await?;

        #[cfg(feature = "files")]
        let (file_transfer_queue, _) =
            broadcast::channel::<FileTransferQueueRequest>(32);

        Ok(Self {
            address: Default::default(),
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            sync_lock: Arc::new(Mutex::new(())),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            #[cfg(feature = "files")]
            file_transfers: None,
            #[cfg(feature = "files")]
            file_transfer_queue,
            offline: options.offline,
            options,
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
        options: NetworkAccountOptions,
    ) -> Result<Self> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            data_dir,
            options,
            |builder| {
                builder
                    .save_passphrase(false)
                    .create_archive(false)
                    .create_authenticator(false)
                    .create_contacts(false)
                    .create_file_password(true)
            },
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
        options: NetworkAccountOptions,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
    ) -> Result<Self> {
        let account = LocalAccount::new_account_with_builder(
            account_name,
            passphrase.clone(),
            data_dir.clone(),
            builder,
        )
        .await?;

        #[cfg(feature = "files")]
        let (file_transfer_queue, _) =
            broadcast::channel::<FileTransferQueueRequest>(32);

        let owner = Self {
            address: account.address().clone(),
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            sync_lock: Arc::new(Mutex::new(())),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            #[cfg(feature = "files")]
            file_transfers: None,
            #[cfg(feature = "files")]
            file_transfer_queue,
            offline: options.offline,
            options,
        };

        Ok(owner)
    }

    /// File transfers queue.
    #[cfg(feature = "files")]
    pub async fn transfers(
        &self,
    ) -> crate::Result<Arc<RwLock<TransfersQueue>>> {
        Ok(self
            .file_transfers
            .as_ref()
            .map(|t| Arc::clone(&t.queue))
            .ok_or_else(|| crate::sdk::Error::NotAuthenticated)?)
    }

    /// Inflight file transfers.
    #[cfg(feature = "files")]
    pub async fn inflight_transfers(&self) -> Result<Arc<InflightTransfers>> {
        Ok(self
            .file_transfers
            .as_ref()
            .map(|t| Arc::clone(&t.inflight))
            .ok_or_else(|| crate::sdk::Error::NotAuthenticated)?)
    }

    /// Convert file mutation events into file transfer queue entries.
    async fn queue_file_mutation_events(
        &self,
        events: &[FileMutationEvent],
    ) -> Result<()> {
        let mut ops = HashMap::new();
        for event in events {
            let (file, op): (ExternalFile, TransferOperation) = event.into();
            let entries = ops.entry(file).or_insert(IndexSet::new());
            entries.insert(op);
        }

        if self.file_transfer_queue.receiver_count() > 0 {
            let _ = self
                .file_transfer_queue
                .send(FileTransferQueueRequest::Pending(ops));
        }

        Ok(())
    }
}

#[async_trait]
impl Account for NetworkAccount {
    type Account = NetworkAccount;
    type Error = Error;

    fn address(&self) -> &Address {
        &self.address
    }

    fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
    }

    async fn is_authenticated(&self) -> bool {
        let account = self.account.lock().await;
        account.is_authenticated().await
    }

    async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        let account = self.account.lock().await;
        Ok(account.account_signer().await?)
    }

    #[cfg(feature = "device")]
    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        let mut account = self.account.lock().await;
        Ok(account.new_device_vault().await?)
    }

    #[cfg(feature = "device")]
    async fn device_signer(&self) -> Result<DeviceSigner> {
        let account = self.account.lock().await;
        Ok(account.device_signer().await?)
    }

    #[cfg(feature = "device")]
    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        let account = self.account.lock().await;
        Ok(account.device_public_key().await?)
    }

    #[cfg(feature = "device")]
    async fn current_device(&self) -> Result<TrustedDevice> {
        let account = self.account.lock().await;
        Ok(account.current_device().await?)
    }

    #[cfg(feature = "device")]
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
    ) -> Result<FolderChange<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.set_folder_description(folder, description).await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
    }

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<AccessKey> {
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
        let conversion = {
            let mut account = self.account.lock().await;
            // Update the local account data.
            account.change_cipher(account_key, cipher, kdf).await?
        };

        let identity = if conversion.identity.is_some() {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            Some(reader.diff(None).await?)
        } else {
            None
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        let identifiers = conversion
            .folders
            .iter()
            .map(|s| *s.id())
            .collect::<Vec<_>>();

        for id in &identifiers {
            let event_log = self.folder_log(id).await?;
            let log_file = event_log.read().await;
            folders.insert(*id, log_file.diff(None).await?);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet { identity, folders };

        let sync_error = self.force_update(&updates, &sync_options).await;
        if let Some(sync_error) = sync_error {
            return Err(Error::ForceUpdate(sync_error));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) = self.sync_with_options(&sync_options).await
        {
            return Err(Error::ForceUpdate(sync_error));
        }

        Ok(conversion)
    }

    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> Result<()> {
        {
            let mut account = self.account.lock().await;
            account.change_account_password(password).await?
        }

        let log = self.identity_log().await?;
        let reader = log.read().await;
        let identity = Some(reader.diff(None).await?);

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet {
            identity,
            folders: Default::default(),
        };

        let sync_error = self.force_update(&updates, &sync_options).await;
        if let Some(sync_error) = sync_error {
            return Err(Error::ForceUpdate(sync_error));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) = self.sync_with_options(&sync_options).await
        {
            return Err(Error::ForceUpdate(sync_error));
        }

        Ok(())
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        self.login(key, Default::default()).await
    }

    async fn sign_in_with_options(
        &mut self,
        key: &AccessKey,
        options: SigninOptions,
    ) -> Result<Vec<Summary>> {
        self.login(key, options).await
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        let account = self.account.lock().await;
        account.verify(key).await
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.open_folder(summary).await?)
    }

    async fn sign_out(&mut self) -> Result<()> {
        #[cfg(feature = "listen")]
        {
            tracing::debug!("net_sign_out::shutdown_listeners");
            self.shutdown_listeners().await;
        }

        #[cfg(feature = "files")]
        {
            tracing::debug!("net_sign_out::stop_file_transfers");
            self.stop_file_transfers().await;
        }

        self.remotes = Default::default();

        let mut account = self.account.lock().await;
        Ok(account.sign_out().await?)
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            let result = account.rename_account(account_name).await?;
            result
        };

        let result = AccountChange {
            event: result.event,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
    }

    async fn delete_account(&mut self) -> Result<()> {
        // Shutdown any change listeners
        #[cfg(feature = "listen")]
        self.shutdown_listeners().await;

        // Stop any pending file transfers
        self.stop_file_transfers().await;

        {
            let mut account = self.account.lock().await;
            // Delete the account and sign out
            account.delete_account().await?;
        }

        Ok(())
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        let account = self.account.lock().await;
        account.find(predicate).await
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        let account = self.account.lock().await;
        Ok(account.storage().await?)
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        let mut account = self.account.lock().await;
        Ok(account.load_folders().await?)
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        let account = self.account.lock().await;
        Ok(account.list_folders().await?)
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        let account = self.account.lock().await;
        Ok(account.secret_ids(summary).await?)
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
        let result = {
            let mut account = self.account.lock().await;
            account.compact_account().await?
        };

        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            Some(reader.diff(None).await?)
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        let identifiers = self
            .list_folders()
            .await?
            .into_iter()
            .map(|s| *s.id())
            .collect::<Vec<_>>();

        for id in &identifiers {
            let event_log = self.folder_log(id).await?;
            let log_file = event_log.read().await;
            folders.insert(*id, log_file.diff(None).await?);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet { identity, folders };

        let sync_error = self.force_update(&updates, &sync_options).await;
        if let Some(sync_error) = sync_error {
            return Err(Error::ForceUpdate(sync_error));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) = self.sync_with_options(&sync_options).await
        {
            return Err(Error::ForceUpdate(sync_error));
        }

        Ok(result)
    }

    async fn compact_folder(
        &mut self,
        folder: &Summary,
    ) -> Result<(AccountEvent, u64, u64)> {
        let result = {
            let mut account = self.account.lock().await;
            account.compact_folder(folder).await?
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        {
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            folders.insert(*folder.id(), log_file.diff(None).await?);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet {
            identity: None,
            folders,
        };

        let sync_error = self.force_update(&updates, &sync_options).await;
        if let Some(sync_error) = sync_error {
            return Err(Error::ForceUpdate(sync_error));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) = self.sync_with_options(&sync_options).await
        {
            return Err(Error::ForceUpdate(sync_error));
        }

        Ok(result)
    }

    async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        {
            let mut account = self.account.lock().await;
            account.change_folder_password(folder, new_key).await?;
        }

        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            Some(reader.diff(None).await?)
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        {
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            folders.insert(*folder.id(), log_file.diff(None).await?);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet { identity, folders };

        let sync_error = self.force_update(&updates, &sync_options).await;
        if let Some(sync_error) = sync_error {
            return Err(Error::ForceUpdate(sync_error));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) = self.sync_with_options(&sync_options).await
        {
            return Err(Error::ForceUpdate(sync_error));
        }

        Ok(())
    }

    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let account = self.account.lock().await;
        Ok(account.detached_view(summary, commit).await?)
    }

    /*
    #[cfg(feature = "files")]
    async fn transfers(
        &self,
    ) -> Result<Arc<RwLock<crate::sdk::storage::files::Transfers>>> {
        let account = self.account.lock().await;
        Ok(account.transfers().await?)
    }
    */

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
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
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
    ) -> Result<SecretChange<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        // Try to sync before we make the change
        self.before_change().await;

        let result = {
            let mut account = self.account.lock().await;
            let result = account.create_secret(meta, secret, options).await?;
            result
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::Error>> {
        // Try to sync before we make the change
        self.before_change().await;

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
                .map(|mut result| {
                    file_events.append(&mut result.file_events);
                    SecretChange {
                        id: result.id,
                        event: result.event,
                        commit_state: result.commit_state,
                        folder: result.folder,
                        sync_error: None,
                        #[cfg(feature = "files")]
                        file_events: result.file_events,
                        marker: std::marker::PhantomData,
                    }
                })
                .collect(),
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&file_events).await?;

        Ok(result)
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        // Try to sync before we make the change
        self.before_change().await;

        let result = {
            let mut account = self.account.lock().await;
            let result = account
                .update_secret(secret_id, meta, secret, options, destination)
                .await?;
            result
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.move_secret(secret_id, from, to, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        let mut account = self.account.lock().await;
        Ok(account.read_secret(secret_id, folder).await?)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        // Try to sync before we make the change
        self.before_change().await;

        let result = {
            let mut account = self.account.lock().await;
            account.delete_secret(secret_id, options).await?
        };

        let result = SecretDelete {
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.archive(from, secret_id, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::Error>, Summary)> {
        let _ = self.sync_lock.lock().await;

        let (result, to) = {
            let mut account = self.account.lock().await;
            account.unarchive(secret_id, secret_meta, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok((result, to))
    }

    #[cfg(feature = "files")]
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Error>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            let result = account
                .update_file(secret_id, meta, path, options, destination)
                .await?;
            result
        };

        let result = SecretChange {
            id: result.id,
            event: result.event,
            commit_state: result.commit_state,
            folder: result.folder,
            sync_error: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
            marker: std::marker::PhantomData,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<FolderCreate<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.create_folder(name).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.rename_folder(summary, name).await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::Error>> {
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    async fn import_identity_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        let mut account = self.account.lock().await;
        Ok(account.import_identity_folder(vault).await?)
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.import_folder_buffer(buffer, key, overwrite).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
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
    ) -> Result<FolderDelete<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.delete_folder(summary).await?
        };

        let result = FolderDelete {
            events: result.events,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let mut account = self.account.lock().await;
        Ok(account.load_avatar(secret_id, folder).await?)
    }

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.export_contact(path, secret_id, folder).await?)
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
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

    #[cfg(feature = "security-report")]
    async fn generate_security_report<T, D, R>(
        &mut self,
        options: SecurityReportOptions<T, D, R>,
    ) -> Result<SecurityReport<T>>
    where
        D: Fn(Vec<String>) -> R + Send + Sync,
        R: std::future::Future<Output = Vec<T>> + Send + Sync,
    {
        let mut account = self.account.lock().await;
        Ok(account.generate_security_report(options).await?)
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
    ) -> Result<FolderCreate<Self::Error>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.import_file(target).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
            marker: std::marker::PhantomData,
        };

        Ok(result)
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
        Ok(LocalAccount::restore_archive_inventory(buffer).await?)
    }

    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        Ok(LocalAccount::import_backup_archive(path, options, data_dir)
            .await?)
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
