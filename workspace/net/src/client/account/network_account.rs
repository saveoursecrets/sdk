//! Network aware account.
use mpc_protocol::generate_keypair;
use secrecy::SecretString;
use sos_sdk::{
    account::{
        Account, AccountBuilder, AccountData, DetachedView, NewAccount,
    },
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    events::{Event, ReadEvent},
    identity::Identity,
    signer::ecdsa::Address,
    storage::{
        search::{
            AccountStatistics, ArchiveFilter, Document, DocumentCount,
            DocumentView, QueryFilter, SearchIndex,
        },
        AccessOptions, FolderStorage,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Summary, VaultId,
    },
    vfs, UserPaths,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};
use tracing::{span, Level};

#[cfg(feature = "listen")]
use crate::client::WebSocketHandle;

use super::sync::{SyncHandler, SyncHandlerData};
use crate::client::{
    HostedOrigin, Origin, Remote, RemoteBridge, RemoteSync, Remotes, Result,
    SyncError,
};

pub(super) type LocalAccount = Account<SyncHandlerData>;

/// Account with networking capability.
pub struct NetworkAccount {
    /// Local account.
    pub(super) account: LocalAccount,

    /// Remote targets for synchronization.
    pub(super) remotes: Arc<RwLock<Remotes>>,

    /// Lock to prevent write to local storage
    /// whilst a sync operation is in progress.
    pub(super) sync_lock: Mutex<()>,

    /// Websocket change listeners.
    #[cfg(feature = "listen")]
    pub(super) listeners: Mutex<Vec<WebSocketHandle>>,
}

impl NetworkAccount {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
        remotes: Option<Remotes>,
    ) -> Result<Self> {
        let remotes = Arc::new(RwLock::new(remotes.unwrap_or_default()));
        let handler = SyncHandler {
            remotes: Arc::clone(&remotes),
        };

        let account = LocalAccount::new_unauthenticated(
            address,
            data_dir,
            Some(Box::new(handler)),
        )
        .await?;

        Ok(Self {
            account,
            remotes,
            sync_lock: Mutex::new(()),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
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
        remotes: Option<Remotes>,
    ) -> Result<(Self, NewAccount)> {
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
            remotes,
        )
        .await
    }

    /// Create a new account with the given
    /// name, passphrase and provider and modify the
    /// account builder.
    pub async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        builder: impl Fn(AccountBuilder) -> AccountBuilder,
        data_dir: Option<PathBuf>,
        remotes: Option<Remotes>,
    ) -> Result<(Self, NewAccount)> {
        let remotes = Arc::new(RwLock::new(remotes.unwrap_or_default()));
        let handler = SyncHandler {
            remotes: Arc::clone(&remotes),
        };

        let (account, new_account) = LocalAccount::new_account_with_builder(
            account_name,
            passphrase.clone(),
            builder,
            data_dir.clone(),
            Some(Box::new(handler)),
        )
        .await?;

        let owner = Self {
            account,
            remotes,
            sync_lock: Mutex::new(()),
            #[cfg(feature = "listen")]
            listeners: Mutex::new(Default::default()),
        };

        Ok((owner, new_account))
    }

    /// Determine if the account is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.account.is_authenticated()
    }

    /// Authenticated user information.
    pub fn user(&self) -> Result<&Identity> {
        Ok(self.account.user()?)
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> Result<&mut Identity> {
        Ok(self.account.user_mut()?)
    }

    /// Storage provider.
    pub fn storage(&self) -> Result<Arc<RwLock<FolderStorage>>> {
        Ok(self.account.storage()?)
    }

    /// Create a remote bridge associated with this local storage and
    /// signing identity and perform the initial noise protocol handshake.
    pub async fn remote_bridge(
        &self,
        origin: &HostedOrigin,
    ) -> Result<RemoteBridge> {
        let keypair = generate_keypair()?;
        let signer = self.user()?.identity()?.signer().clone();
        let local = self.storage()?;
        let provider =
            RemoteBridge::new(local, origin.clone(), signer, keypair)?;

        // Noise protocol handshake
        provider.handshake().await?;

        Ok(provider)
    }

    /// Insert a remote origin for synchronization.
    ///
    /// If a remote with the given origin already exists it is
    /// overwritten.
    pub async fn insert_remote(
        &mut self,
        origin: Origin,
        remote: Remote,
    ) -> Result<()> {
        let mut remotes = self.remotes.write().await;
        remotes.insert(origin, remote);
        self.save_remotes(&*remotes).await
    }

    /// Delete a remote if it exists.
    pub async fn delete_remote(
        &mut self,
        origin: &Origin,
    ) -> Result<Option<Remote>> {
        let mut remotes = self.remotes.write().await;
        let remote = remotes.remove(origin);
        self.save_remotes(&*remotes).await?;
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

    /// Account address.
    pub fn address(&self) -> &Address {
        self.account.address()
    }

    /// Sign in to an account.
    pub async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let folders = self.account.sign_in(key).await?;

        // Load origins from disc and create remote definitions
        let remotes_file = self.paths().remote_origins();
        if vfs::try_exists(&remotes_file).await? {
            let contents = vfs::read(&remotes_file).await?;
            let origins: Vec<Origin> = serde_json::from_slice(&contents)?;
            let mut remotes: Remotes = Default::default();
            for origin in origins {
                match &origin {
                    Origin::Hosted(host) => {
                        let remote = self.remote_bridge(host).await?;
                        remotes.insert(origin, Box::new(remote));
                    }
                }
            }
            self.remotes = Arc::new(RwLock::new(remotes));
        }

        Ok(folders)
    }

    /// User storage paths.
    pub fn paths(&self) -> &UserPaths {
        self.account.paths()
    }

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to authenticate other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the master password for this account.
    pub async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        Ok(self.account.identity_vault_buffer().await?)
    }

    /// Compute the user statistics.
    pub async fn statistics(&self) -> AccountStatistics {
        self.account.statistics().await
    }

    /// Account data.
    pub async fn account_data(&self) -> Result<AccountData> {
        Ok(self.account.account_data().await?)
    }

    /// Verify an access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        self.account.verify(key).await
    }

    /// Delete the account for this user and sign out.
    pub async fn delete_account(&mut self) -> Result<()> {
        // Delete the account and sign out
        self.account.delete_account().await?;
        // Shutdown any change listeners
        #[cfg(feature = "listen")]
        self.shutdown_listeners().await;
        Ok(())
    }

    /// Rename this account.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        Ok(self.account.rename_account(account_name).await?)
    }

    /// Try to find a folder using a predicate.
    pub async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool,
    {
        self.account.find(predicate).await
    }

    /// Find the default folder.
    pub async fn default_folder(&self) -> Option<Summary> {
        self.account.default_folder().await
    }

    /// Find the authenticator folder.
    pub async fn authenticator_folder(&self) -> Option<Summary> {
        self.account.authenticator_folder().await
    }

    /// Find the contacts folder.
    pub async fn contacts_folder(&self) -> Option<Summary> {
        self.account.contacts_folder().await
    }

    /// Find the archive folder.
    pub async fn archive_folder(&self) -> Option<Summary> {
        self.account.archive_folder().await
    }

    /// Load folders from disc into memory.
    pub async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        Ok(self.account.load_folders().await?)
    }

    /// List folders managed by this account.
    pub async fn list_folders(&mut self) -> Result<Vec<Summary>> {
        Ok(self.account.list_folders().await?)
    }

    /// Sign out of the account.
    pub async fn sign_out(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());
        #[cfg(feature = "listen")]
        self.shutdown_listeners().await;

        self.remotes = Default::default();

        Ok(self.account.sign_out().await?)
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

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let (summary, event, commit_state, secure_key) =
            self.account.create_folder(name).await?;

        let sync_error = self
            .sync_send_events(&summary, &commit_state, &[event])
            .await
            .err();

        Ok((summary, sync_error))
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<Option<SyncError>> {
        let _ = self.sync_lock.lock().await;

        let (events, commit_state) =
            self.account.delete_folder(summary).await?;

        let sync_error = self
            .sync_send_events(&summary, &commit_state, &events)
            .await
            .err();

        Ok(sync_error)
    }

    /// Rename a folder.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<Option<SyncError>> {
        let _ = self.sync_lock.lock().await;

        let (event, commit_state) =
            self.account.rename_folder(summary, name).await?;

        let sync_error = self
            .sync_send_events(&summary, &commit_state, &[event])
            .await
            .err();

        Ok(sync_error)
    }

    /// Export a folder as a vault file.
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        Ok(self
            .account
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
        Ok(self
            .account
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

        let (summary, event, commit_state) = self
            .account
            .import_folder_buffer(buffer, key, overwrite)
            .await?;

        let sync_error = self
            .sync_send_events(&summary, &commit_state, &[event])
            .await
            .err();

        Ok((summary, sync_error))
    }

    /// Open a vault.
    pub async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        Ok(self.account.open_folder(summary).await?)
    }

    /// Bulk insert secrets into the currently open folder.
    pub async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<Vec<(SecretId, Event, CommitState, Summary)>> {
        Ok(self.account.insert_secrets(secrets).await?)
    }

    /// Create a secret in the current open folder or a specific folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<(SecretId, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let (id, event, commit_state, folder) =
            self.account.create_secret(meta, secret, options).await?;

        let sync_error = self
            .sync_send_events(&folder, &commit_state, &[event])
            .await
            .err();

        Ok((id, sync_error))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        Ok(self.account.read_secret(secret_id, folder).await?)
    }

    /// Update a file secret.
    ///
    /// If the secret exists and is not a file secret it will be
    /// converted to a file secret so take care to ensure you only
    /// use this on file secrets.
    #[cfg(feature = "files")]
    pub async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let (id, event, commit_state, folder) = self
            .account
            .update_file(secret_id, meta, path, options, destination)
            .await?;

        let sync_error = self
            .sync_send_events(&folder, &commit_state, &[event])
            .await
            .err();

        Ok((id, sync_error))
    }

    /// Update a secret in the current open folder or a specific folder.
    pub async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let (id, event, commit_state, folder) = self
            .account
            .update_secret(secret_id, meta, secret, options, destination)
            .await?;

        let sync_error = self
            .sync_send_events(&folder, &commit_state, &[event])
            .await
            .err();

        Ok((id, sync_error))
    }

    /// Move a secret between folders.
    pub async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        let _ = self.sync_lock.lock().await;
        Ok(self
            .account
            .move_secret(secret_id, from, to, options)
            .await?)
    }

    /// Delete a secret and remove any external files.
    pub async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<Option<SyncError>> {
        let _ = self.sync_lock.lock().await;

        let (event, commit_state, folder) =
            self.account.delete_secret(secret_id, options).await?;

        let sync_error = self
            .sync_send_events(&folder, &commit_state, &[event])
            .await
            .err();

        Ok(sync_error)
    }

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    pub async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        let _ = self.sync_lock.lock().await;

        Ok(self.account.archive(from, secret_id, options).await?)
    }

    /// Move a secret out of the archive.
    ///
    /// The secret must be inside a folder with the archive flag set.
    pub async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(Summary, SecretId, Event)> {
        let _ = self.sync_lock.lock().await;
        Ok(self
            .account
            .unarchive(from, secret_id, secret_meta, options)
            .await?)
    }

    /*
    /// Search index reference.
    pub fn index(&self) -> Result<&AccountSearch> {
        Ok(self.account.index()?)
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        Ok(self.account.index_mut()?)
    }
    */

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        Ok(self.account.initialize_search_index().await?)
    }

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    pub async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        Ok(self.account.detached_view(summary, commit).await?)
    }

    /// Get the root commit hash for a folder.
    pub async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        Ok(self.account.root_commit(summary).await?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    pub async fn commit_state(
        &self,
        summary: &Summary,
    ) -> Result<CommitState> {
        Ok(self.account.commit_state(summary).await?)
    }

    /// Compact an event log file.
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        Ok(self.account.compact(summary).await?)
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

    /// Decrypt a file so it can be downloaded from the account.
    #[cfg(feature = "files")]
    pub async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        Ok(self
            .account
            .download_file(vault_id, secret_id, file_name)
            .await?)
    }
}

// Search functions
impl NetworkAccount {
    /// Search index for the account.
    pub async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        Ok(self.account.index().await?)
    }

    /// Query with document views.
    pub async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        Ok(self.account.query_view(views, archive).await?)
    }

    /// Query the search index.
    pub async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        Ok(self.account.query_map(query, filter).await?)
    }

    /// Get the search index document count statistics.
    pub async fn document_count(&self) -> Result<DocumentCount> {
        Ok(self.account.document_count().await?)
    }

    /// Determine if a document exists in a folder.
    pub async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        Ok(self.account.document_exists(vault_id, label, id).await?)
    }
}
