//! Network aware account.
use async_trait::async_trait;
use secrecy::SecretString;
use sos_sdk::{
    account::{
        Account, AccountBuilder, AccountData, DetachedView, LocalAccount,
        SecretChange, SecretDelete, SecretInsert, SecretMove, FolderCreate,
        FolderRename,
    },
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    device::{DevicePublicKey, DeviceSigner},
    events::{Event, ReadEvent},
    identity::{AccountRef, PublicIdentity},
    sha2::{Digest, Sha256},
    signer::ecdsa::{Address, BoxedEcdsaSigner},
    storage::{
        files::FileTransfers,
        search::{
            AccountStatistics, ArchiveFilter, Document, DocumentCount,
            DocumentView, QueryFilter, SearchIndex,
        },
        AccessOptions, ClientStorage,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Summary, VaultId,
    },
    vfs, Paths,
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    oneshot, Mutex, RwLock,
};
use tracing::{span, Level};

#[cfg(feature = "listen")]
use crate::client::WebSocketHandle;

use crate::client::{
    Error, Origin, Remote, RemoteBridge, RemoteSync, Remotes, Result,
    SyncError,
};

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
    pub(super) sync_lock: Mutex<()>,

    /// Websocket change listeners.
    #[cfg(feature = "listen")]
    pub(super) listeners: Mutex<Vec<WebSocketHandle>>,

    /// Identifier for this client connection.
    ///
    /// When listening for changes use the same identifier
    /// so the server can filter out broadcast messages
    /// made by this client.
    connection_id: Option<String>,

    /// Shutdown handle for the file transfers background task.
    file_transfers: Option<(UnboundedSender<()>, oneshot::Receiver<()>)>,
}

impl NetworkAccount {
    /// Enroll a new device.
    #[cfg(feature = "device")]
    pub async fn enroll(
        origin: Origin,
        account_signing_key: BoxedEcdsaSigner,
        data_dir: Option<PathBuf>,
    ) -> Result<crate::client::enrollment::DeviceEnrollment> {
        use crate::client::{enrollment::DeviceEnrollment, RpcClient};
        use crate::sdk::signer::ed25519::BoxedEd25519Signer;

        let address = account_signing_key.address()?;
        let enrollment = DeviceEnrollment::new(
            &address,
            data_dir.clone(),
            origin.clone(),
        )?;
        let device_signing_key = enrollment.device_signing_key.clone();
        let device: BoxedEd25519Signer = device_signing_key.into();
        let remote = RpcClient::new(
            origin,
            account_signing_key,
            device,
            String::new(),
        )?;

        enrollment.enroll(remote).await?;

        Ok(enrollment)
    }

    /// Revoke a device.
    #[cfg(feature = "device")]
    pub async fn revoke_device(
        &mut self,
        device_key: &crate::sdk::device::DevicePublicKey,
    ) -> Result<()> {
        // Update the local device event log
        {
            let account = self.account.lock().await;
            let storage = account.storage().await?;
            let mut storage = storage.write().await;
            storage.revoke_device(device_key).await?;
        }

        // Send the device event logs to the remote servers
        if let Some(e) = self.patch_devices().await {
            tracing::error!(error = ?e);
            return Err(Error::RevokeDeviceSync);
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
                let device_signer = self.device_signer().await?;
                let device_public_key = device_signer.public_key();

                hasher.update(docs_path.as_bytes());
                hasher.update(device_public_key.as_ref());
            }

            let result = hasher.finalize();
            hex::encode(&result)
        })
    }

    /// Clone of the local account.
    pub fn local_account(&self) -> Arc<Mutex<LocalAccount>> {
        Arc::clone(&self.account)
    }

    /// Determine if the account is authenticated.
    pub async fn is_authenticated(&self) -> bool {
        let account = self.account.lock().await;
        account.is_authenticated()
    }

    /// Find the password for a folder.
    pub async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<AccessKey> {
        let account = self.account.lock().await;
        Ok(account.user()?.find_folder_password(folder_id).await?)
    }

    /// Generate the password for a folder.
    pub async fn generate_folder_password(&self) -> Result<SecretString> {
        let account = self.account.lock().await;
        Ok(account.user()?.generate_folder_password()?)
    }

    /// Signing key for the account.
    pub async fn account_signer(&self) -> Result<BoxedEcdsaSigner> {
        let account = self.account.lock().await;
        Ok(account.user()?.identity()?.signer().clone())
    }

    /// Public key for the device signing key.
    pub async fn device_public_key(&self) -> Result<DevicePublicKey> {
        let account = self.account.lock().await;
        let device = account.user()?.identity()?.device();
        Ok(device.public_key())
    }

    async fn device_signer(&self) -> Result<DeviceSigner> {
        let account = self.account.lock().await;
        Ok(account.user()?.identity()?.device().clone())
    }

    /// Add a server backend.
    pub async fn add_server(&mut self, origin: Origin) -> Result<()> {
        let provider = self.remote_bridge(&origin).await?;
        self.insert_remote(origin.into(), Box::new(provider)).await
    }

    /// Insert a remote origin for synchronization.
    ///
    /// If a remote with the given origin already exists it is
    /// overwritten.
    async fn insert_remote(
        &mut self,
        origin: Origin,
        remote: Remote,
    ) -> Result<()> {
        {
            let mut remotes = self.remotes.write().await;
            remotes.insert(origin, remote);
            self.save_remotes(&*remotes).await?;
        }
        self.start_file_transfers().await
    }

    /// Create a remote bridge associated with this local storage and
    /// signing identity.
    async fn remote_bridge(&self, origin: &Origin) -> Result<RemoteBridge> {
        let signer = self.account_signer().await?;
        let device = self.device_signer().await?;
        let provider = RemoteBridge::new(
            Arc::clone(&self.account),
            origin.clone(),
            signer,
            device.into(),
            self.client_connection_id().await?,
        )?;
        Ok(provider)
    }

    /// Delete a remote if it exists.
    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub async fn delete_remote(
        &mut self,
        origin: &Origin,
    ) -> Result<Option<Remote>> {
        let remote = {
            let mut remotes = self.remotes.write().await;
            let remote = remotes.remove(origin);
            self.save_remotes(&*remotes).await?;
            remote
        };
        self.start_file_transfers().await?;
        Ok(remote)
    }

    /// List the origin servers.
    pub async fn servers(&self) -> Vec<Origin> {
        let remotes = self.remotes.read().await;
        remotes.keys().cloned().collect()
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
        let remotes = self.remotes.read().await;
        for remote in remotes.values() {
            if let Some(e) = remote.sync().await {
                tracing::error!(error = ?e, "failed to sync before change");
            }
        }
    }

    /// Spawn a task to handle file transfers.
    async fn start_file_transfers(&mut self) -> Result<()> {
        if !self.is_authenticated().await {
            return Err(crate::sdk::Error::NotAuthenticated.into());
        }

        // Stop any existing transfers task
        self.stop_file_transfers().await;

        let clients = {
            let remotes = self.remotes.read().await;
            let mut clients = Vec::new();
            for (_, remote) in &*remotes {
                if let Some(remote) =
                    remote.as_any().downcast_ref::<RemoteBridge>()
                {
                    clients.push(remote.client().clone());
                }
            }
            clients
        };

        let (paths, transfers) = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            (reader.paths(), reader.transfers())
        };

        let (shutdown_send, shutdown_recv) = mpsc::unbounded_channel::<()>();
        let (ack_send, ack_recv) = oneshot::channel::<()>();

        FileTransfers::start(
            paths,
            transfers,
            clients,
            shutdown_recv,
            ack_send,
        );

        self.file_transfers = Some((shutdown_send, ack_recv));
        Ok(())
    }

    /// Stop a file transfers task.
    async fn stop_file_transfers(&mut self) {
        if let Some((shutdown, ack)) = self.file_transfers.take() {
            let _ = shutdown.send(());
            let _ = ack.await;
        }
    }

    /// Close all the websocket connections
    #[cfg(feature = "listen")]
    async fn shutdown_listeners(&self) {
        let mut listeners = self.listeners.lock().await;
        for handle in listeners.drain(..) {
            tracing::debug!("close websocket");
            handle.close();
        }
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<Option<SyncError>> {
        let _ = self.sync_lock.lock().await;
        {
            let mut account = self.account.lock().await;
            account.delete_folder(summary).await?;
        }
        Ok(self.sync().await)
    }

    /// Export a folder as a vault file.
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account
            .export_folder(path, summary, new_key, save_key)
            .await?)
    }

    /// Export a folder to a buffer.
    pub async fn export_folder_buffer(
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

    /// Import a vault file to a folder.
    pub async fn import_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Option<SyncError>)> {
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    /// Import a vault buffer to a folder.
    pub async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let summary = {
            let mut account = self.account.lock().await;
            let (summary, _, _) =
                account.import_folder_buffer(buffer, key, overwrite).await?;
            summary
        };

        Ok((summary, self.sync().await))
    }

    /// Expected location for a file by convention.
    pub fn file_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> PathBuf {
        self.paths().file_location(vault_id, secret_id, file_name)
    }
}

#[async_trait]
impl Account for NetworkAccount {
    type Account = NetworkAccount;
    type Error = Error;

    async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let account =
            LocalAccount::new_unauthenticated(address, data_dir).await?;
        Ok(Self {
            address: Default::default(),
            paths: Arc::clone(&account.paths),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            sync_lock: Mutex::new(()),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            file_transfers: None,
        })
    }

    async fn new_account(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            |builder| {
                builder
                    .save_passphrase(false)
                    .create_archive(false)
                    .create_authenticator(false)
                    .create_contacts(false)
                    .create_file_password(true)
            },
            data_dir,
        )
        .await
    }

    async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let account = LocalAccount::new_account_with_builder(
            account_name,
            passphrase.clone(),
            builder,
            data_dir.clone(),
        )
        .await?;

        let owner = Self {
            address: account.address().clone(),
            paths: Arc::clone(&account.paths),
            account: Arc::new(Mutex::new(account)),
            remotes: Arc::new(RwLock::new(Default::default())),
            sync_lock: Mutex::new(()),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
            connection_id: None,
            file_transfers: None,
        };

        Ok(owner)
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn paths(&self) -> &Paths {
        &self.paths
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        let account = self.account.lock().await;
        Ok(account.public_identity().await?)
    }

    async fn account_ref(&self) -> Result<AccountRef> {
        let account = self.account.lock().await;
        Ok(account.account_ref().await?)
    }

    async fn account_label(&self) -> Result<String> {
        let account = self.account.lock().await;
        Ok(account.account_label().await?)
    }

    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let account = self.account.lock().await;
        Ok(account.identity_vault_buffer().await?)
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let folders = {
            let mut account = self.account.lock().await;
            let folders = account.sign_in(key).await?;
            self.paths = Arc::clone(&account.paths);
            self.address = account.address().clone();
            folders
        };

        // Load origins from disc and create remote definitions
        let remotes_file = self.paths().remote_origins();
        if vfs::try_exists(&remotes_file).await? {
            let contents = vfs::read(&remotes_file).await?;
            let origins: HashSet<Origin> = serde_json::from_slice(&contents)?;
            let mut remotes: Remotes = Default::default();

            for origin in origins {
                let remote = self.remote_bridge(&origin).await?;
                remotes.insert(origin, Box::new(remote));
            }

            self.remotes = Arc::new(RwLock::new(remotes));

            self.start_file_transfers().await?;
        }

        Ok(folders)
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
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());
        #[cfg(feature = "listen")]
        self.shutdown_listeners().await;

        self.stop_file_transfers().await;
        {
            let transfers = self.transfers().await?;
            let mut transfers = transfers.write().await;
            transfers.clear();
        }

        self.remotes = Default::default();

        let mut account = self.account.lock().await;
        Ok(account.sign_out().await?)
    }

    async fn rename_account(&mut self, account_name: String) -> Result<()> {
        let mut account = self.account.lock().await;
        Ok(account.rename_account(account_name).await?)
    }

    async fn delete_account(&mut self) -> Result<()> {
        let mut account = self.account.lock().await;
        // Delete the account and sign out
        account.delete_account().await?;
        // Shutdown any change listeners
        #[cfg(feature = "listen")]
        self.shutdown_listeners().await;
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

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let mut account = self.account.lock().await;
        Ok(account.compact(summary).await?)
    }

    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let account = self.account.lock().await;
        Ok(account.detached_view(summary, commit).await?)
    }

    #[cfg(feature = "files")]
    async fn transfers(
        &self,
    ) -> Result<Arc<RwLock<crate::sdk::storage::files::Transfers>>> {
        let account = self.account.lock().await;
        Ok(account.transfers().await?)
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
        };

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

        let result = SecretInsert {
            results: result
                .results
                .into_iter()
                .map(|result| SecretChange {
                    id: result.id,
                    event: result.event,
                    commit_state: result.commit_state,
                    folder: result.folder,
                    sync_error: None,
                })
                .collect(),
            sync_error: self.sync().await,
        };

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
        };

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
        };

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
        };

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
        };

        Ok(result)
    }

    async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::Error>, Summary)> {
        let _ = self.sync_lock.lock().await;

        let (result, to) = {
            let mut account = self.account.lock().await;
            account
                .unarchive(from, secret_id, secret_meta, options)
                .await?
        };

        let result = SecretMove {
            id: result.id,
            event: result.event,
            sync_error: self.sync().await,
        };

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
        };

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
        };

        Ok(result)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<FolderRename<Self::Error>> {
        let _ = self.sync_lock.lock().await;
        let result = {
            let mut account = self.account.lock().await;
            account.rename_folder(summary, name).await?
        };
        
        let result = FolderRename {
            event: result.event,
            commit_state: result.commit_state,
            sync_error: self.sync().await,
        };

        Ok(result)
    }

}
