//! Network aware account.
use crate::{Error, RemoteBridge, Result};
use async_trait::async_trait;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use sos_account::{
    Account, AccountBuilder, AccountChange, AccountData, CipherComparison,
    FolderChange, FolderCreate, FolderDelete, LocalAccount, SecretChange,
    SecretDelete, SecretInsert, SecretMove,
};
use sos_backend::{Folder, ServerOrigins};
use sos_client_storage::{AccessOptions, NewFolderOptions};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::{AccessKey, Cipher, KeyDerivation},
    device::{DevicePublicKey, TrustedDevice},
    events::{AccountEvent, EventLog, EventLogType, EventRecord, ReadEvent},
    AccountId, AccountRef, Origin, Paths, PublicIdentity, RemoteOrigins,
    SecretId, VaultId,
};
use sos_login::device::{DeviceManager, DeviceSigner};
use sos_protocol::{
    AccountSync, DiffRequest, RemoteSync, RemoteSyncHandler, SyncClient,
    SyncOptions, SyncResult,
};
use sos_sdk::events::{DeviceEvent, WriteEvent};
use sos_sdk::UtcDateTime;
use sos_sync::{CreateSet, StorageEventLogs, UpdateSet};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    FolderRef, Summary, Vault, VaultCommit, VaultFlags,
};
use sos_vfs as vfs;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "clipboard")]
use {
    sos_account::{xclipboard::Clipboard, ClipboardCopyRequest},
    sos_core::SecretPath,
};

#[cfg(feature = "search")]
use sos_search::{
    AccountStatistics, ArchiveFilter, Document, DocumentCount, DocumentView,
    QueryFilter, SearchIndex,
};

#[cfg(feature = "archive")]
use sos_filesystem::archive::{Inventory, RestoreOptions};

use indexmap::IndexSet;

#[cfg(feature = "contacts")]
use sos_account::ContactImportProgress;

#[cfg(feature = "archive")]
use tokio::io::{AsyncRead, AsyncSeek};

#[cfg(feature = "migrate")]
use sos_migrate::import::ImportTarget;

#[cfg(feature = "listen")]
use sos_protocol::network_client::WebSocketHandle;

#[cfg(feature = "audit")]
use {
    sos_audit::{AuditData, AuditEvent},
    sos_backend::audit::append_audit_events,
    sos_core::events::EventKind,
};

/*
#[cfg(feature = "security-report")]
use crate::sdk::account::security_report::{
    SecurityReport, SecurityReportOptions,
};
*/

use super::remote::Remotes;

#[cfg(feature = "files")]
use {
    crate::account::file_transfers::{
        FileTransferSettings, FileTransfers, FileTransfersHandle,
        InflightTransfers,
    },
    sos_external_files::FileMutationEvent,
    sos_protocol::{network_client::HttpClient, transfer::FileOperation},
};

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
    /// Account identifier.
    account_id: AccountId,

    /// Paths for the account.
    paths: Arc<Paths>,

    /// Local account.
    pub(super) account: Arc<Mutex<LocalAccount>>,

    /// Remote targets for synchronization.
    pub(super) remotes: Arc<RwLock<Remotes>>,

    /// Server origins for this account.
    server_origins: Option<ServerOrigins>,

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
    file_transfers: Option<FileTransfers<HttpClient>>,

    /// Handle to a file transfers event loop.
    #[cfg(feature = "files")]
    file_transfer_handle: Option<FileTransfersHandle>,

    /// Disable networking.
    pub(crate) offline: bool,

    /// Options for the network account.
    #[allow(dead_code)]
    options: NetworkAccountOptions,
}

impl NetworkAccount {
    async fn login(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let folders = {
            let mut account = self.account.lock().await;
            let folders = account.sign_in(key).await?;
            self.paths = account.paths();
            self.account_id = *account.account_id();
            folders
        };

        // Without an explicit connection id use the inferred
        // connection identifier
        if self.connection_id.is_none() {
            self.connection_id = self.client_connection_id().await.ok();
        }

        let server_origins = ServerOrigins::new_fs(self.paths());
        let servers = server_origins.list_servers().await?;

        // Initialize remote bridges for each server origin
        if !servers.is_empty() {
            let mut remotes: Remotes = Default::default();
            for origin in servers {
                let remote = self.remote_bridge(&origin).await?;
                remotes.insert(origin, remote);
            }
            self.remotes = Arc::new(RwLock::new(remotes));
        }

        self.server_origins = Some(server_origins);
        self.activate().await?;

        Ok(folders)
    }

    /// Deactive this account by closing down long-running tasks.
    ///
    /// Does not sign out of the account so is similar to moving
    /// this account to the background so the data is still accessible.
    ///
    /// This can be used when implementing quick account switching
    /// to shutdown the websocket and file transfers.
    ///
    /// Server remotes are left intact so that making changes
    /// will still sync with server(s).
    pub async fn deactivate(&mut self) {
        #[cfg(feature = "listen")]
        {
            tracing::debug!("net_sign_out::shutdown_websockets");
            self.shutdown_websockets().await;
        }

        #[cfg(feature = "files")]
        {
            tracing::debug!("net_sign_out::stop_file_transfers");
            self.stop_file_transfers().await;
        }
    }

    /// Activate this account by resuming websocket connections
    /// and file transfers.
    pub async fn activate(&mut self) -> Result<()> {
        #[cfg(feature = "files")]
        {
            let clients = {
                let mut clients = Vec::new();
                let remotes = self.remotes.read().await;
                for (_, remote) in &*remotes {
                    clients.push(remote.client().clone());
                }
                clients
            };

            let file_transfers = FileTransfers::new(
                clients,
                self.options.file_transfer_settings.clone(),
            );
            self.file_transfers = Some(file_transfers);
            self.start_file_transfers().await?;
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
    /// An initial sync is performed with the server and the result
    /// includes a possible error encountered during the initial sync.
    ///
    /// If a server with the given origin already exists it is
    /// overwritten.
    pub async fn add_server(
        &mut self,
        origin: Origin,
    ) -> Result<Option<Error>> {
        #[cfg(feature = "files")]
        {
            let remote = self.remote_bridge(&origin).await?;

            if let Some(file_transfers) = self.file_transfers.as_mut() {
                file_transfers.add_client(remote.client().clone()).await;
            };

            let mut remotes = self.remotes.write().await;
            if let Some(handle) = &self.file_transfer_handle {
                self.proxy_remote_file_queue(handle, &remote).await;
            }
            remotes.insert(origin.clone(), remote);
            self.server_origins
                .as_mut()
                .unwrap()
                .add_server(origin.clone())
                .await?;
            // self.save_remotes(&*remotes).await?;
        }

        let mut sync_error = None;
        {
            let remotes = self.remotes.read().await;
            if let Some(remote) = remotes.get(&origin) {
                let options = SyncOptions {
                    origins: vec![origin.clone()],
                    ..Default::default()
                };
                if let Err(err) =
                    remote.sync_with_options(&options).await.result
                {
                    sync_error = Some(err);
                }
            }
        }

        tracing::debug!(url = %origin.url(), "server::added");
        if let Some(sync_error) = &sync_error {
            tracing::warn!(
                sync_error = ?sync_error,
                "server::initial_sync_failed");
        }

        Ok(sync_error)
    }

    /// Replace a server origin with updated origin information.
    pub async fn replace_server(
        &mut self,
        old_origin: &Origin,
        new_origin: Origin,
    ) -> Result<bool> {
        // Note that this works because Origin only includes
        // the url for it's Hash implementation
        let mut remotes = self.remotes.write().await;
        if let Some(remote) = remotes.remove(&old_origin) {
            remotes.insert(new_origin.clone(), remote);
            self.server_origins
                .as_mut()
                .unwrap()
                .replace_server(old_origin, new_origin)
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove a server.
    pub async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<Option<RemoteBridge>> {
        let remote = {
            let mut remotes = self.remotes.write().await;
            let remote = remotes.remove(origin);
            #[allow(unused_variables)]
            if let Some(remote) = &remote {
                #[cfg(feature = "files")]
                if let Some(file_transfers) = self.file_transfers.as_mut() {
                    file_transfers.remove_client(remote.client()).await;
                }
                self.server_origins
                    .as_mut()
                    .unwrap()
                    .remove_server(origin)
                    .await?;
            }
            remote
        };

        tracing::debug!(url = %origin.url(), "server::removed");
        Ok(remote)
    }

    /// Create a remote bridge between this account and the origin server.
    async fn remote_bridge(&self, origin: &Origin) -> Result<RemoteBridge> {
        let device = self.device_signer().await?;
        let conn_id = if let Some(conn_id) = &self.connection_id {
            conn_id.to_string()
        } else {
            self.client_connection_id().await?
        };
        let provider = RemoteBridge::new(
            *self.account_id(),
            Arc::clone(&self.account),
            origin.clone(),
            device.into(),
            conn_id,
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

    /// Try to recover a folder from a remote origin; it is an
    /// error if the folder exists in memory or on disc.
    pub async fn recover_remote_folder(
        &mut self,
        origin: &Origin,
        folder_id: &VaultId,
    ) -> Result<Summary> {
        let folders = self.list_folders().await?;
        if folders.iter().find(|f| f.id() == folder_id).is_some() {
            return Err(Error::FolderExists(*folder_id));
        }

        let vault_path = self.paths.vault_path(folder_id);
        let event_path = self.paths.event_log_path(folder_id);

        if vfs::try_exists(&vault_path).await? {
            return Err(Error::FileExists(vault_path));
        }

        if vfs::try_exists(&event_path).await? {
            return Err(Error::FileExists(event_path));
        }

        self.recover_remote_folder_unchecked(origin, folder_id)
            .await
    }

    /// Try to recover a folder from a remote origin.
    ///
    /// If the folder already exists on disc it is overwritten.
    async fn recover_remote_folder_unchecked(
        &mut self,
        origin: &Origin,
        folder_id: &VaultId,
    ) -> Result<Summary> {
        let _ = self.sync_lock.lock().await;
        let remote = self.remote_bridge(origin).await?;
        let request = DiffRequest {
            log_type: EventLogType::Folder(*folder_id),
            from_hash: None,
        };
        let response = remote.client().diff(request).await?;
        self.restore_folder(folder_id, response.patch).await
    }

    /// Spawn a task to handle file transfers.
    #[cfg(feature = "files")]
    async fn start_file_transfers(&mut self) -> Result<()> {
        if !self.is_authenticated().await {
            return Err(sos_account::Error::NotAuthenticated.into());
        }

        if self.offline {
            tracing::warn!("offline mode active, ignoring file transfers");
            return Ok(());
        }

        // Stop any existing transfers task
        self.stop_file_transfers().await;

        let paths = self.paths();
        if let Some(file_transfers) = &mut self.file_transfers {
            tracing::debug!("file_transfers::start");

            let handle = file_transfers.run(paths);

            {
                // Proxy file transfer queue events from the
                // remote bridges to the file transfer event loop
                let remotes = self.remotes.read().await;
                for (_, remote) in &*remotes {
                    self.proxy_remote_file_queue(&handle, remote).await;
                }
            }

            self.file_transfer_handle = Some(handle);
        }

        Ok(())
    }

    #[cfg(feature = "files")]
    async fn proxy_remote_file_queue(
        &self,
        handle: &FileTransfersHandle,
        remote: &RemoteBridge,
    ) {
        let mut rx = remote.file_transfer_queue.subscribe();
        let tx = handle.queue_tx.clone();
        tokio::task::spawn(async move {
            while let Ok(event) = rx.recv().await {
                let res = tx.send(event).await;
                if let Err(error) = res {
                    tracing::error!(error = ?error);
                }
            }
            Ok::<_, Error>(())
        });
    }

    /// Stop a file transfers task.
    #[cfg(feature = "files")]
    async fn stop_file_transfers(&mut self) {
        if let Some(handle) = self.file_transfer_handle.take() {
            handle.shutdown().await;
        }
    }
}

impl From<&NetworkAccount> for AccountRef {
    fn from(value: &NetworkAccount) -> Self {
        Self::Id(*value.account_id())
    }
}

impl NetworkAccount {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        account_id: AccountId,
        data_dir: Option<PathBuf>,
        options: NetworkAccountOptions,
        // offline: bool,
    ) -> Result<Self> {
        let account =
            LocalAccount::new_unauthenticated(account_id, data_dir).await?;

        Ok(Self {
            account_id,
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            server_origins: None,
            sync_lock: Arc::new(Mutex::new(())),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            #[cfg(feature = "files")]
            file_transfers: None,
            #[cfg(feature = "files")]
            file_transfer_handle: None,
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

        let owner = Self {
            account_id: *account.account_id(),
            paths: account.paths(),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            server_origins: None,
            sync_lock: Arc::new(Mutex::new(())),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            #[cfg(feature = "files")]
            file_transfers: None,
            #[cfg(feature = "files")]
            file_transfer_handle: None,
            offline: options.offline,
            options,
        };

        Ok(owner)
    }

    /// Inflight file transfers.
    #[cfg(feature = "files")]
    pub fn inflight_transfers(&self) -> Result<Arc<InflightTransfers>> {
        Ok(self
            .file_transfers
            .as_ref()
            .map(|t| Arc::clone(&t.inflight))
            .ok_or_else(|| sos_account::Error::NotAuthenticated)?)
    }

    /// Convert file mutation events into file transfer queue entries.
    #[cfg(feature = "files")]
    async fn queue_file_mutation_events(
        &self,
        events: &[FileMutationEvent],
    ) -> Result<()> {
        if let Some(handle) = &self.file_transfer_handle {
            let mut items = Vec::with_capacity(events.len());
            for event in events {
                let item: FileOperation = event.into();
                items.push(item);
            }

            handle.send(items).await;
        }

        Ok(())
    }
}

#[async_trait]
impl Account for NetworkAccount {
    type Error = Error;
    type NetworkResult = SyncResult<Self::Error>;

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
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
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.patch_devices_unchecked(events).await?)
    }

    async fn revoke_device(
        &mut self,
        device_key: &DevicePublicKey,
    ) -> Result<()> {
        let current_device = self.current_device().await?;
        if current_device.public_key() == device_key {
            return Err(Error::RevokeDeviceSelf);
        }

        // Update the local device event log
        {
            let mut account = self.account.lock().await;
            account.revoke_device(device_key).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::RevokeDevice,
                *self.account_id(),
                Some(AuditData::Device(*device_key)),
            );
            append_audit_events(&[audit_event]).await?;
        }

        // Send the device event logs to the remote servers
        if let Some(e) = self.sync().await.first_error() {
            tracing::error!(error = ?e);
            return Err(Error::RevokeDeviceSync(Box::new(e)));
        }

        Ok(())
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
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.set_folder_description(folder, description).await?
        };

        let result = FolderChange {
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
        };

        Ok(result)
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

    async fn reload_identity_folder(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.reload_identity_folder().await?)
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
            let diff = reader.diff_unchecked().await?;
            Some(diff)
        } else {
            None
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();

        for folder in &conversion.folders {
            if folder.flags().is_sync_disabled() {
                continue;
            }
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            let diff = log_file.diff_unchecked().await?;
            folders.insert(*folder.id(), diff);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet {
            identity,
            folders,
            ..Default::default()
        };

        let sync_result = self.force_update(updates, &sync_options).await;
        if let Some(sync_error) = sync_result.first_error() {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) =
            self.sync_with_options(&sync_options).await.first_error()
        {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
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
        let identity = reader.diff_unchecked().await?;

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet {
            identity: Some(identity),
            ..Default::default()
        };

        let sync_result = self.force_update(updates, &sync_options).await;
        if let Some(sync_error) = sync_result.first_error() {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) =
            self.sync_with_options(&sync_options).await.first_error()
        {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
        }

        Ok(())
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        self.login(key).await
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

    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let account = self.account.lock().await;
        Ok(account.history(folder_id).await?)
    }

    async fn sign_out(&mut self) -> Result<()> {
        self.deactivate().await;
        self.remotes = Default::default();
        self.server_origins = None;

        #[cfg(feature = "files")]
        {
            self.file_transfers.take();
        }

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

    async fn delete_account(&mut self) -> Result<()> {
        // Shutdown any change listeners
        #[cfg(feature = "listen")]
        self.shutdown_websockets().await;

        // Stop any pending file transfers
        #[cfg(feature = "files")]
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

    async fn find_folder(&self, vault: &FolderRef) -> Option<Summary> {
        let account = self.account.lock().await;
        account.find_folder(vault).await
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
    ) -> Result<HashMap<Summary, AccountEvent>> {
        let result = {
            let mut account = self.account.lock().await;
            account.compact_account().await?
        };

        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            reader.diff_unchecked().await?
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        let compact_folders = self.list_folders().await?;

        for folder in &compact_folders {
            if folder.flags().is_sync_disabled() {
                continue;
            }
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            let diff = log_file.diff_unchecked().await?;
            folders.insert(*folder.id(), diff);
        }

        // Force update the folders on remote servers
        let sync_options: SyncOptions = Default::default();
        let updates = UpdateSet {
            identity: Some(identity),
            folders,
            ..Default::default()
        };

        let sync_result = self.force_update(updates, &sync_options).await;
        if let Some(sync_error) = sync_result.first_error() {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
        }

        // In case we have pending updates to the account, device
        // or file event logs
        if let Some(sync_error) =
            self.sync_with_options(&sync_options).await.first_error()
        {
            return Err(Error::ForceUpdate(Box::new(sync_error)));
        }

        Ok(result)
    }

    async fn compact_folder(
        &mut self,
        folder: &Summary,
    ) -> Result<AccountEvent> {
        let result = {
            let mut account = self.account.lock().await;
            account.compact_folder(folder).await?
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        if !folder.flags().is_sync_disabled() {
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            let diff = log_file.diff_unchecked().await?;
            folders.insert(*folder.id(), diff);
        }

        if !folders.is_empty() {
            // Force update the folders on remote servers
            let sync_options: SyncOptions = Default::default();
            let updates = UpdateSet {
                identity: None,
                folders,
                ..Default::default()
            };

            let sync_result = self.force_update(updates, &sync_options).await;
            if let Some(sync_error) = sync_result.first_error() {
                return Err(Error::ForceUpdate(Box::new(sync_error)));
            }

            // In case we have pending updates to the account, device
            // or file event logs
            if let Some(sync_error) =
                self.sync_with_options(&sync_options).await.first_error()
            {
                return Err(Error::ForceUpdate(Box::new(sync_error)));
            }
        }

        Ok(result)
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
        {
            let mut account = self.account.lock().await;
            account.change_folder_password(folder, new_key).await?;
        }

        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            reader.diff_unchecked().await?
        };

        // Prepare event logs for the folders that
        // were converted
        let mut folders = HashMap::new();
        if !folder.flags().is_sync_disabled() {
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            let diff = log_file.diff_unchecked().await?;
            folders.insert(*folder.id(), diff);
        }

        if !folders.is_empty() {
            // Force update the folders on remote servers
            let sync_options: SyncOptions = Default::default();
            let updates = UpdateSet {
                identity: Some(identity),
                folders,
                ..Default::default()
            };

            let sync_result = self.force_update(updates, &sync_options).await;
            if let Some(sync_error) = sync_result.first_error() {
                return Err(Error::ForceUpdate(Box::new(sync_error)));
            }

            // In case we have pending updates to the account, device
            // or file event logs
            if let Some(sync_error) =
                self.sync_with_options(&sync_options).await.first_error()
            {
                return Err(Error::ForceUpdate(Box::new(sync_error)));
            }
        }

        Ok(())
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<sos_account::DetachedView> {
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

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

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
                        sync_result: Default::default(),
                        #[cfg(feature = "files")]
                        file_events: result.file_events,
                    }
                })
                .collect(),
            sync_result: self.sync().await,
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
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account
                .update_secret(secret_id, meta, secret, options, destination)
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

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

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
    ) -> std::result::Result<Option<(VaultCommit, ReadEvent)>, Self::Error>
    {
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

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.archive(from, secret_id, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
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
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        let _ = self.sync_lock.lock().await;

        let (result, to) = {
            let mut account = self.account.lock().await;
            account.unarchive(secret_id, secret_meta, options).await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
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
    ) -> Result<SecretChange<Self::NetworkResult>> {
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
            sync_result: self.sync().await,
            #[cfg(feature = "files")]
            file_events: result.file_events,
        };

        #[cfg(feature = "files")]
        self.queue_file_mutation_events(&result.file_events).await?;

        Ok(result)
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.create_folder(name, options).await?
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
        summary: &Summary,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.rename_folder(summary, name).await?
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
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.update_folder_flags(summary, flags).await?
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
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.delete_folder(summary).await?
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

    /*
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
    */

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
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.import_file(target).await?
        };

        let result = FolderCreate {
            folder: result.folder,
            event: result.event,
            commit_state: result.commit_state,
            sync_result: self.sync().await,
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

    #[cfg(feature = "clipboard")]
    async fn copy_clipboard(
        &self,
        clipboard: &Clipboard,
        target: &SecretPath,
        request: &ClipboardCopyRequest,
    ) -> Result<bool> {
        let account = self.account.lock().await;
        Ok(account.copy_clipboard(clipboard, target, request).await?)
    }
}
