//! Network aware account.
use std::{
    any::Any,
    path::{Path, PathBuf},
    sync::Arc,
};

use sos_sdk::{
    account::{
        archive::{Inventory, RestoreOptions},
        search::{AccountSearch, AccountStatistics, DocumentCount},
        AccessOptions, Account, AccountBuilder, AccountData, AccountHandler,
        AccountInfo, AuthenticatedUser, DetachedView, FolderStorage,
        NewAccount, UserPaths,
    },
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    events::{Event, ReadEvent},
    mpc::generate_keypair,
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Summary, VaultId,
    },
    vfs,
};

#[cfg(feature = "contacts")]
use sos_sdk::account::contacts::ContactImportProgress;

#[cfg(feature = "security-report")]
pub use sos_sdk::account::security_report::{
    SecurityReport, SecurityReportOptions,
};

use tracing::{span, Level};

use secrecy::SecretString;
use tokio::{
    io::{AsyncRead, AsyncSeek},
    sync::{Mutex, RwLock},
};

#[cfg(not(target_arch = "wasm32"))]
use crate::client::WebSocketHandle;
use crate::client::{
    sync::SyncData, Error, Origin, Remote, RemoteBridge, RemoteSync, Remotes,
    Result, SyncError, SyncOptions,
};

use async_trait::async_trait;

#[cfg(feature = "device")]
use super::devices::DeviceManager;

type SyncHandlerData = Arc<RwLock<Remotes>>;
type LocalAccount = Account<SyncHandlerData>;

struct SyncHandler {
    remotes: Arc<RwLock<Remotes>>,
}

impl SyncHandler {
    /// Try to sync the target folder against all remotes.
    async fn try_sync_folder(
        &self,
        storage: Arc<RwLock<FolderStorage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Result<Option<CommitState>> {
        let mut changed = false;
        let (last_commit, commit_proof) = commit_state;
        let mut last_commit = last_commit.clone();
        let mut commit_proof = commit_proof.clone();

        let remotes = self.remotes.read().await;
        for remote in remotes.values() {
            let local_changed = remote
                .sync_folder(folder, commit_state, None, &Default::default())
                .await?;

            // If a remote changes were applied to local
            // we need to recompute the last commit and client proof
            if local_changed {
                let reader = storage.read().await;
                let event_log = reader
                    .cache()
                    .get(folder.id())
                    .ok_or(Error::CacheNotAvailable(*folder.id()))?;
                last_commit = event_log
                    .last_commit()
                    .await?
                    .ok_or(Error::NoRootCommit)?;
                commit_proof = event_log.tree().head()?;
            }

            changed = changed || local_changed;
        }

        Ok(if changed {
            Some((last_commit, commit_proof))
        } else {
            None
        })
    }
}

#[async_trait::async_trait]
impl AccountHandler for SyncHandler {
    type Data = SyncHandlerData;

    fn data(&self) -> &Self::Data {
        &self.remotes
    }

    async fn before_change(
        &self,
        storage: Arc<RwLock<FolderStorage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Option<CommitState> {
        match self.try_sync_folder(storage, folder, commit_state).await {
            Ok(commit_state) => commit_state,
            Err(e) => {
                tracing::error!(error = ?e, "failed to sync before change");
                None
            }
        }
    }
}

/// Authenticated user with local storage provider.
pub struct UserStorage {
    /// Local account.
    account: LocalAccount,

    /// Devices for this user.
    #[cfg(feature = "device")]
    devices: DeviceManager,

    /// Remote targets for synchronization.
    pub(super) remotes: Arc<RwLock<Remotes>>,

    /// Lock to prevent write to local storage
    /// whilst a sync operation is in progress.
    pub(super) sync_lock: Mutex<()>,

    /// Websocket change listeners.
    #[cfg(not(target_arch = "wasm32"))]
    listeners: Mutex<Vec<WebSocketHandle>>,
}

impl UserStorage {
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
        let devices_dir = account.paths().devices_dir().clone();

        Ok(Self {
            account,
            #[cfg(feature = "device")]
            devices: DeviceManager::new(devices_dir)?,
            remotes,
            sync_lock: Mutex::new(()),
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
                    .save_passphrase(true)
                    .create_archive(true)
                    .create_authenticator(false)
                    .create_contacts(true)
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

        let devices_dir = account.paths().devices_dir().clone();

        let owner = Self {
            account,
            #[cfg(feature = "device")]
            devices: DeviceManager::new(devices_dir)?,
            remotes,
            sync_lock: Mutex::new(()),
            listeners: Mutex::new(Default::default()),
        };

        Ok((owner, new_account))
    }

    /// Determine if the account is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.account.is_authenticated()
    }

    /// Authenticated user information.
    pub fn user(&self) -> Result<&AuthenticatedUser> {
        Ok(self.account.user()?)
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> Result<&mut AuthenticatedUser> {
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
        origin: &Origin,
    ) -> Result<RemoteBridge> {
        let keypair = generate_keypair()?;
        let signer = self.user()?.identity().signer().clone();
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
    pub async fn insert_remote(&mut self, origin: Origin, remote: Remote) {
        let mut remotes = self.remotes.write().await;
        remotes.insert(origin, remote);
    }

    /*
    /// Get a remote.
    pub fn get_remote(&self, origin: &Origin) -> Option<&Remote> {
        self.remotes.get(origin)
    }
    */

    /// Delete a remote if it exists.
    pub async fn delete_remote(&mut self, origin: &Origin) -> Option<Remote> {
        let mut remotes = self.remotes.write().await;
        remotes.remove(origin)
    }

    /// Account address.
    pub fn address(&self) -> &Address {
        self.account.address()
    }

    /// Sign in to an account.
    pub async fn sign_in(&mut self, passphrase: SecretString) -> Result<()> {
        Ok(self.account.sign_in(passphrase).await?)
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
        Ok(self.account.delete_account().await?)

        /*
        let event = self.user.delete_account(&self.paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;
        self.sign_out().await;
        Ok(())
        */
    }

    /// Rename this account.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        Ok(self.account.rename_account(account_name).await?)
    }

    /// Users devices reference.
    #[cfg(feature = "device")]
    pub fn devices(&self) -> &DeviceManager {
        &self.devices
    }

    /// Users devices mutable reference.
    #[cfg(feature = "device")]
    pub fn devices_mut(&mut self) -> &mut DeviceManager {
        &mut self.devices
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

        // Close all the websocket connections
        {
            let mut listeners = self.listeners.lock().await;
            for handle in listeners.drain(..) {
                tracing::debug!("close websocket");
                handle.close();
            }
        }

        Ok(self.account.sign_out().await?)
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
            .sync_send_events(
                &summary,
                &commit_state,
                &[event],
                &[SyncData::CreateVault(secure_key)],
            )
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

        let (event, commit_state) =
            self.account.delete_folder(summary).await?;

        let sync_error = self
            .sync_send_events(&summary, &commit_state, &[event], &[])
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
            .sync_send_events(&summary, &commit_state, &[event], &[])
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
            .sync_send_events(&summary, &commit_state, &[event], &[])
            .await
            .err();

        Ok((summary, sync_error))
    }

    /// Open a vault.
    pub async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        Ok(self.account.open_folder(summary).await?)
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
            .sync_send_events(&folder, &commit_state, &[event], &[])
            .await
            .err();

        Ok((id, sync_error))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretData, ReadEvent)> {
        Ok(self.account.read_secret(secret_id, folder).await?)
    }

    /// Update a file secret.
    ///
    /// If the secret is not the `File` variant that it will be
    /// converted to a `File` variant to ensure this is only called
    /// on file secrets.
    pub async fn update_file<P: AsRef<Path>>(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: P,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let (id, event, commit_state, folder) = self
            .account
            .update_file(secret_id, meta, path, options, destination)
            .await?;

        let sync_error = self
            .sync_send_events(&folder, &commit_state, &[event], &[])
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
            .sync_send_events(&folder, &commit_state, &[event], &[])
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
            .sync_send_events(&folder, &commit_state, &[event], &[])
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

    /// Search index reference.
    pub fn index(&self) -> Result<&AccountSearch> {
        Ok(self.account.index()?)
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        Ok(self.account.index_mut()?)
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        Ok(self.account.initialize_search_index().await?)
    }

    /// Build the search index for all folders.
    pub async fn build_search_index(&mut self) -> Result<DocumentCount> {
        Ok(self.account.build_search_index().await?)
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

    /// Expected location for a file by convention.
    pub fn file_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> PathBuf {
        self.paths().file_location(
            vault_id.to_string(),
            secret_id.to_string(),
            file_name,
        )
    }

    /// Decrypt a file so it can be downloaded from the account.
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

    /// Generate a security report.
    #[cfg(feature = "security-report")]
    pub async fn generate_security_report<T, D, R>(
        &mut self,
        options: SecurityReportOptions<T, D, R>,
    ) -> Result<SecurityReport<T>>
    where
        D: Fn(Vec<String>) -> R,
        R: std::future::Future<Output = Vec<T>>,
    {
        Ok(self.account.generate_security_report(options).await?)
    }
}

#[cfg(feature = "migrate")]
use sos_migrate::{import::ImportTarget, AccountExport, AccountImport};

#[cfg(feature = "migrate")]
impl UserStorage {
    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        let migration = AccountExport::new(&self.account);
        Ok(migration.export_unsafe_archive(path).await?)
    }

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        let _ = self.sync_lock.lock().await;
        let mut migration = AccountImport::new(&mut self.account);
        Ok(migration.import_file(target).await?)
    }
}

#[cfg(feature = "archive")]
impl UserStorage {
    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub async fn export_backup_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        Ok(self.account.export_backup_archive(path).await?)
    }

    /// Read the inventory from an archive.
    pub async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        Ok(LocalAccount::restore_archive_inventory(buffer).await?)
    }

    /// Import from an archive file.
    pub async fn restore_backup_archive<P: AsRef<Path>>(
        owner: Option<&mut UserStorage>,
        path: P,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<AccountInfo> {
        Ok(LocalAccount::restore_backup_archive(
            owner.map(|o| &mut o.account),
            path,
            options,
            data_dir,
        )
        .await?)
    }
}

#[cfg(feature = "contacts")]
impl UserStorage {
    /// Get an avatar JPEG image for a contact in the current
    /// open folder.
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self.account.load_avatar(secret_id, folder).await?)
    }

    /// Export a contact secret to vCard file.
    pub async fn export_vcard_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        Ok(self
            .account
            .export_vcard_file(path, secret_id, folder)
            .await?)
    }

    /// Export all contacts to a single vCard.
    pub async fn export_all_vcards<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        Ok(self.account.export_all_vcards(path).await?)
    }

    /// Import vCards from a string buffer.
    pub async fn import_vcard(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress),
    ) -> Result<()> {
        Ok(self.account.import_vcard(content, progress).await?)
    }
}

#[async_trait]
impl RemoteSync for UserStorage {
    async fn sync(&self) -> Option<SyncError> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(e) = remote.sync_with_options(options).await {
                    match e {
                        SyncError::One(e) => errors.push((origin.clone(), e)),
                        SyncError::Multiple(mut errs) => {
                            errors.append(&mut errs)
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            None
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Some(SyncError::Multiple(errors))
        }
    }

    async fn sync_folder(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        remote_state: Option<CommitState>,
        options: &SyncOptions,
    ) -> std::result::Result<bool, SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let mut changed = false;
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                match remote
                    .sync_folder(
                        folder,
                        commit_state,
                        remote_state.clone(),
                        options,
                    )
                    .await
                {
                    Ok(changes) => {}
                    Err(e) => match e {
                        SyncError::One(e) => errors.push((origin.clone(), e)),
                        SyncError::Multiple(mut errs) => {
                            errors.append(&mut errs)
                        }
                    },
                }
            }
        }
        if errors.is_empty() {
            Ok(changed)
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Err(SyncError::Multiple(errors))
        }
    }

    async fn sync_send_events(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        events: &[Event],
        data: &[SyncData],
    ) -> std::result::Result<(), SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            if let Err(e) = remote
                .sync_send_events(folder, commit_state, events, data)
                .await
            {
                match e {
                    SyncError::One(e) => errors.push((origin.clone(), e)),
                    SyncError::Multiple(mut errs) => errors.append(&mut errs),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SyncError::Multiple(errors))
        }
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod listen {
    use super::LocalAccount;
    use crate::client::{
        account::remote::{UserStorageReceiver, UserStorageSender},
        Error, ListenOptions, Origin, RemoteBridge, Result, UserStorage,
        WebSocketHandle,
    };
    use futures::{select, FutureExt};
    use sos_sdk::prelude::SecureAccessKey;
    use std::sync::Arc;

    impl UserStorage {
        /// Listen for changes on a remote origin.
        pub async fn listen(
            &self,
            origin: &Origin,
            options: ListenOptions,
        ) -> Result<WebSocketHandle> {
            let remotes = self.remotes.read().await;
            if let Some(remote) = remotes.get(origin) {
                if let Some(remote) =
                    remote.as_any().downcast_ref::<RemoteBridge>()
                {
                    let remote = Arc::new(remote.clone());
                    let (handle, rx, tx) =
                        RemoteBridge::listen(remote, options);
                    self.spawn_remote_bridge_channels(rx, tx);

                    // Store the listeners so we can
                    // close the connections on sign out
                    let mut listeners = self.listeners.lock().await;
                    listeners.push(handle.clone());

                    Ok(handle)
                } else {
                    unreachable!();
                }
            } else {
                Err(Error::OriginNotFound(origin.clone()))
            }
        }

        fn spawn_remote_bridge_channels(
            &self,
            mut rx: UserStorageReceiver,
            tx: UserStorageSender,
        ) {
            if self.account.is_authenticated() {
                let user = self.user().unwrap();
                let keeper = user.identity().keeper();
                let secret_key = user.identity().signer().to_bytes();

                // TODO: needs shutdown hook so this loop exits
                // TODO: when the websocket connection is closed
                tokio::task::spawn(async move {
                    loop {
                        select!(
                            event = rx
                                .secure_access_key_rx
                                .recv()
                                .fuse() => {
                                if let Some((folder_id, secure_key)) = event {

                                    // Decrypt the secure access key received
                                    // when creating or importing a folder,
                                    // must be done here as the remote bridge
                                    // does not have access to the private key
                                    // (account signing key)
                                    let access_key = SecureAccessKey::decrypt(
                                        &secure_key,
                                        secret_key.clone(),
                                    )
                                    .await?;

                                    // Save the access key for the synced folder
                                    let identity = Arc::clone(&keeper);
                                    LocalAccount::save_folder_password(
                                        identity,
                                        &folder_id,
                                        access_key.clone(),
                                    )
                                    .await?;

                                    tx.access_key_tx.send(access_key).await?;
                                }
                            }
                            event = rx
                                .remove_vault_rx
                                .recv()
                                .fuse() => {
                                if let Some(folder_id) = event {
                                    // When a folder is removed via remote
                                    // bridge changes we need to clean up the
                                    // passphrase
                                    let identity = Arc::clone(&keeper);
                                    LocalAccount::remove_folder_password(
                                        identity,
                                        &folder_id,
                                    )
                                    .await?;
                                }
                            }
                        )
                    }
                    Ok::<(), Error>(())
                });
            }
        }
    }
}
