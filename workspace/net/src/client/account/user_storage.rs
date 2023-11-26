//! Network aware account.
use std::{
    any::Any,
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use futures::Future;

use sos_sdk::{
    account::{
        archive::Inventory, Account, AccountBackup, AccountBuilder,
        AccountData, AccountInfo, AuthenticatedUser, DelegatedPassphrase,
        DetachedView, ExtractFilesLocation, ImportedAccount, LocalAccounts,
        LocalProvider, Login, NewAccount, RestoreOptions, SecretOptions,
        UserIndex, UserPaths, UserStatistics,
        AccountHandler,
    },
    commit::{CommitHash, CommitProof, CommitState},
    crypto::{AccessKey, SecureAccessKey},
    decode, encode,
    events::{
        AccountEvent, AuditData, AuditEvent, AuditLogFile, AuditProvider,
        Event, EventKind, EventReducer, ReadEvent, WriteEvent,
    },
    mpc::generate_keypair,
    search::{DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta, SecretType},
        Gatekeeper, Summary, Vault, VaultId,
    },
    vfs::{self, File},
    Timestamp,
};

#[cfg(feature = "contacts")]
use sos_sdk::account::ContactImportProgress;

#[cfg(feature = "security-report")]
pub use sos_sdk::account::{SecurityReport, SecurityReportOptions};

use tracing::{span, Level};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::{
    io::{AsyncRead, AsyncSeek},
    sync::{mpsc, Mutex, RwLock},
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

#[cfg(feature = "migrate")]
use sos_migrate::{
    import::{ImportFormat, ImportTarget},
    Convert,
};


type SyncHandlerData = Arc<RwLock<Remotes>>;
type LocalAccount = Account<SyncHandlerData>;

struct SyncHandler {
    remotes: Arc<RwLock<Remotes>>,
}

impl SyncHandler {

    /// Try to sync the target folder against all remotes.
    async fn try_sync_folder(
        &self,
        storage: Arc<RwLock<LocalProvider>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Result<Option<CommitState>> {
        let mut changed = false;
        let (last_commit, commit_proof) = commit_state;
        let mut last_commit = last_commit.clone();
        let mut commit_proof = commit_proof.clone();
        
        let remotes = self.remotes.read().await;
        for remote in remotes.values() {
            let local_changed = remote.sync_folder(
                folder, commit_state, None, &Default::default()).await?;

            // If a remote changes were applied to local
            // we need to recompute the last commit and client proof
            if local_changed {
                let reader = storage.read().await;
                let event_log = reader
                    .cache()
                    .get(folder.id())
                    .ok_or(Error::CacheNotAvailable(*folder.id()))?;
                last_commit = event_log.last_commit().await?
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
        storage: Arc<RwLock<LocalProvider>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Option<CommitState> {
        match self
            .try_sync_folder(
                storage,
                folder,
                commit_state,
            )
            .await
        {
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
    ) -> Result<(Self, ImportedAccount, NewAccount)> {
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
    ) -> Result<(Self, ImportedAccount, NewAccount)> {
        let remotes = Arc::new(RwLock::new(remotes.unwrap_or_default()));
        let handler = SyncHandler {
            remotes: Arc::clone(&remotes),
        };

        let (account, imported_account, new_account) =
            LocalAccount::new_account_with_builder(
                account_name,
                passphrase.clone(),
                builder,
                data_dir.clone(),
                Some(Box::new(handler)),
            )
            .await?;

        let devices_dir = account.paths().devices_dir().clone();

        // TODO: don't automatically sign in on new account?

        let owner = Self::sign_in(
            new_account.user.address(),
            passphrase,
            data_dir.clone(),
        )
        .await?;
        
        /*
        let owner = Self {
            account,
            #[cfg(feature = "device")]
            devices: DeviceManager::new(devices_dir)?,
            remotes,
            sync_lock: Mutex::new(()),
            listeners: Mutex::new(Default::default()),
        };
        */

        Ok((owner, imported_account, new_account))
    }

    /// Authenticated user information.
    pub fn user(&self) -> &AuthenticatedUser {
        self.account.user()
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> &mut AuthenticatedUser {
        self.account.user_mut()
    }

    /// Storage provider.
    pub fn storage(&self) -> Arc<RwLock<LocalProvider>> {
        self.account.storage()
    }

    /// Create a remote bridge associated with this local storage and
    /// signing identity and perform the initial noise protocol handshake.
    pub async fn remote_bridge(
        &self,
        origin: &Origin,
    ) -> Result<RemoteBridge> {
        let keypair = generate_keypair()?;
        let signer = self.account.user().identity().signer().clone();
        let local = self.storage();
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

    /// File storage directory.
    pub fn files_dir(&self) -> &PathBuf {
        self.account.files_dir()
    }

    /// User identity address.
    pub fn address(&self) -> &Address {
        self.account.address()
    }

    /// Sign in to an existing account.
    pub async fn sign_in(
        address: &Address,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let remotes = Arc::new(RwLock::new(Default::default()));
        // TODO: load existing remote definitions from disc
        let handler = SyncHandler {
            remotes: Arc::clone(&remotes),
        };

        let account = LocalAccount::sign_in(
            address,
            passphrase,
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

    /// User storage paths.
    pub fn paths(&self) -> &UserPaths {
        self.account.paths()
    }

    /*
    /// Append to the audit log.
    async fn append_audit_logs(&self, events: Vec<AuditEvent>) -> Result<()> {
        let mut writer = self.audit_log.write().await;
        writer.append_audit_events(events).await?;
        Ok(())
    }
    */

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
    pub async fn statistics(&self) -> UserStatistics {
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

    /// List folders.
    pub async fn list_folders(&mut self) -> Result<Vec<Summary>> {
        Ok(self.account.list_folders().await?)
    }

    /// Sign out of the account.
    pub async fn sign_out(&mut self) {
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

        self.account.sign_out().await;
    }

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        /*
        let passphrase = DelegatedPassphrase::generate_vault_passphrase()?;
        let key = AccessKey::Password(passphrase);
        let (buffer, _, summary) = {
            let mut writer = self.storage.write().await;
            writer.create_vault(name, Some(key.clone())).await?
        };

        let secret_key = self.user.identity().signer().to_bytes();
        let secure_key =
            SecureAccessKey::encrypt(&key, secret_key, None).await?;

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
            key,
        )
        .await?;

        let event = Event::Account(AccountEvent::CreateFolder(*summary.id()));
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        let options = SecretOptions {
            folder: Some(summary),
            ..Default::default()
        };
        let (summary, before_last_commit, before_commit_proof) =
            self.before_apply_events(&options, false).await?;

        //let (_, event) = event.try_into()?;
        let event = WriteEvent::CreateVault(buffer);
        */

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
    
    /*
    /// Helper to get all the state information needed
    /// before calling sync methods.
    ///
    /// Computes the target folder that will be used, the last commit
    /// hash and the proof for the current head of the events log.
    async fn before_apply_events(
        &self,
        options: &SecretOptions,
        apply_changes: bool,
    ) -> Result<(Summary, Option<CommitHash>, CommitProof)> {
        let (folder, mut last_commit, mut commit_proof) = {
            let reader = self.storage.read().await;
            let folder = options
                .folder
                .clone()
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?;

            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            let last_commit = event_log.last_commit().await?;
            let commit_proof = event_log.tree().head()?;
            (folder, last_commit, commit_proof)
        };

        // Most sync events should try to apply remote changes
        // beforehand but some (such as creating new folders) should
        // not as it would just result in a 404
        if apply_changes {
            match self
                .sync_before_apply_change(
                    &folder,
                    last_commit.as_ref(),
                    &commit_proof,
                )
                .await
            {
                Ok(changed) => {
                    // If changes were made we need to re-compute the
                    // proof and last commit
                    if changed {
                        let reader = self.storage.read().await;
                        let event_log = reader
                            .cache()
                            .get(folder.id())
                            .ok_or(Error::CacheNotAvailable(*folder.id()))?;
                        last_commit = event_log.last_commit().await?;
                        commit_proof = event_log.tree().head()?;
                    }
                }
                Err(e) => {
                    tracing::error!(error = ?e, "failed to sync before change");
                }
            }
        }

        Ok((folder, last_commit, commit_proof))
    }
    */

    /// Create a secret in the current open folder or a specific folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: SecretOptions,
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
        options: SecretOptions,
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
        mut options: SecretOptions,
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
        options: SecretOptions,
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
        mut options: SecretOptions,
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
        options: SecretOptions,
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
        options: SecretOptions,
    ) -> Result<(Summary, SecretId, Event)> {
        let _ = self.sync_lock.lock().await;
        Ok(self
            .account
            .unarchive(from, secret_id, secret_meta, options)
            .await?)
    }

    /// Search index reference.
    pub fn index(&self) -> &UserIndex {
        self.account.index()
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> &mut UserIndex {
        self.account.index_mut()
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

    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    #[cfg(feature = "migrate")]
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        use sos_migrate::export::PublicExport;
        use std::io::Cursor;

        let local_accounts = LocalAccounts::new(self.paths());

        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = local_accounts.list_local_vaults(false).await?;

        for (summary, _) in vaults {
            let (vault, _) =
                local_accounts.find_local_vault(summary.id(), false).await?;
            let vault_passphrase =
                DelegatedPassphrase::find_vault_passphrase(
                    self.account.user().identity().keeper(),
                    summary.id(),
                )
                .await?;

            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(vault_passphrase.into()).await?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper).await?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer =
            serde_json::to_vec_pretty(self.account.user().account())?;
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files).await?;
        migration.finish().await?;

        vfs::write(path.as_ref(), &archive).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportUnsafe,
            self.address().clone(),
            None,
        );
        self.account.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        let _ = self.sync_lock.lock().await;

        use sos_migrate::import::csv::{
            bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
            dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
            macos::MacPasswordCsv, one_password::OnePasswordCsv,
        };

        let (event, summary) = match target.format {
            ImportFormat::OnePasswordCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    OnePasswordCsv,
                )
                .await?
            }
            ImportFormat::DashlaneZip => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    DashlaneCsvZip,
                )
                .await?
            }
            ImportFormat::BitwardenCsv => {
                self.import_csv(target.path, target.folder_name, BitwardenCsv)
                    .await?
            }
            ImportFormat::ChromeCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    ChromePasswordCsv,
                )
                .await?
            }
            ImportFormat::FirefoxCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    FirefoxPasswordCsv,
                )
                .await?
            }
            ImportFormat::MacosCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    MacPasswordCsv,
                )
                .await?
            }
        };

        let audit_event = AuditEvent::new(
            EventKind::ImportUnsafe,
            self.address().clone(),
            None,
        );
        let create_event: AuditEvent = (self.address(), &event).into();
        self.account.append_audit_logs(vec![audit_event, create_event])
            .await?;

        Ok(summary)
    }

    /// Generic CSV import implementation.
    #[cfg(feature = "migrate")]
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<(Event, Summary)> {
        use sos_sdk::vault::VaultBuilder;

        let local_accounts = LocalAccounts::new(self.paths());

        let vaults = local_accounts.list_local_vaults(false).await?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == folder_name);

        let vault_passphrase =
            DelegatedPassphrase::generate_vault_passphrase()?;

        let vault_id = VaultId::new_v4();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault_id)
        } else {
            folder_name
        };

        let vault = VaultBuilder::new()
            .id(vault_id)
            .public_name(name)
            .password(vault_passphrase.clone(), None)
            .await?;

        // Parse the CSV records into the vault
        let vault = converter
            .convert(
                path.as_ref().to_path_buf(),
                vault,
                vault_passphrase.clone().into(),
            )
            .await?;

        let buffer = encode(&vault).await?;
        let (event, summary) = {
            let storage = self.account.storage();
            let mut writer = storage.write().await;
            writer.import_vault(buffer).await?
        };

        DelegatedPassphrase::save_vault_passphrase(
            self.account.user().identity().keeper(),
            vault.id(),
            vault_passphrase.clone().into(),
        )
        .await?;

        // Ensure the imported secrets are in the search index
        self.index_mut()
            .add_folder_to_search_index(vault, vault_passphrase.into())
            .await?;

        let event = Event::Write(*summary.id(), event);
        Ok((event, summary))
    }

    /// Get an avatar JPEG image for a contact in the current
    /// open folder.
    #[cfg(feature = "contacts")]
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self.account.load_avatar(secret_id, folder).await?)
    }

    /// Export a contact secret to vCard file.
    #[cfg(feature = "contacts")]
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
    #[cfg(feature = "contacts")]
    pub async fn export_all_vcards<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        Ok(self.account.export_all_vcards(path).await?)
    }

    /// Import vCards from a string buffer.
    #[cfg(feature = "contacts")]
    pub async fn import_vcard(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress),
    ) -> Result<()> {
        Ok(self.account.import_vcard(content, progress).await?)
    }

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
    pub async fn decrypt_file_storage(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        Ok(self
            .account
            .decrypt_file_storage(vault_id, secret_id, file_name)
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

impl From<UserStorage> for Arc<RwLock<LocalProvider>> {
    fn from(value: UserStorage) -> Self {
        value.account.into()
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

    /*
    async fn sync_before_apply_change(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        client_proof: &CommitProof,
    ) -> Result<bool> {
        let mut changed = false;
        let mut last_commit = last_commit.clone();
        let mut client_proof = client_proof.clone();

        let _ = self.sync_lock.lock().await;
        for remote in self.remotes.values() {
            let local_changed = remote
                .sync_before_apply_change(folder, &last_commit, &client_proof)
                .await?;

            // If a remote changes were applied to local
            // we need to recompute the last commit and client proof
            if local_changed {
                let reader = self.storage.read().await;
                let event_log = reader
                    .cache()
                    .get(folder.id())
                    .ok_or(Error::CacheNotAvailable(*folder.id()))?;
                last_commit = event_log.last_commit().await?;
                client_proof = event_log.tree().head()?;
            }

            changed = changed || local_changed;
        }
        Ok(changed)
    }
    */

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
    use crate::client::{
        account::remote::{UserStorageReceiver, UserStorageSender},
        Error, ListenOptions, Origin, RemoteBridge, Result, UserStorage,
        WebSocketHandle,
    };
    use futures::{select, Future, FutureExt};
    use sos_sdk::prelude::{
        CommitHash, CommitProof, DelegatedPassphrase, SecureAccessKey,
        Summary,
    };
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
            let keeper = self.account.user().identity().keeper();
            let secret_key =
                self.account.user().identity().signer().to_bytes();

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
                                DelegatedPassphrase::save_vault_passphrase(
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
                                DelegatedPassphrase::remove_vault_passphrase(
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
