//! Account storage and search index..as_ref()
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use crate::{
    account::{
        search::{AccountStatistics, DocumentCount, SearchIndex},
        AccountBuilder, FolderKeys, FolderStorage, Identity, NewAccount,
        UserPaths,
    },
    commit::{CommitHash, CommitState},
    constants::VAULT_EXT,
    crypto::{AccessKey, SecureAccessKey},
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, AuditData, AuditEvent, AuditLogFile,
        AuditProvider, Event, EventKind, EventReducer, ReadEvent, WriteEvent,
    },
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretType},
        Gatekeeper, Header, Summary, Vault, VaultId,
    },
    vfs, Error, Result, Timestamp,
};

use tracing::{span, Level};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use super::search::AccountSearch;
use async_trait::async_trait;

#[cfg(feature = "files")]
use crate::{
    account::files::FileProgress,
    events::{FileEvent, FileEventLog},
};

/// Type alias for a local account without a handler.
pub type LocalAccount = Account<()>;

/// Account handler is notified of account changes.
#[async_trait]
pub trait AccountHandler {
    /// Data associated with this handler.
    type Data;

    /// Called before changes to the account.
    async fn before_change(
        &self,
        storage: Arc<RwLock<FolderStorage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Option<CommitState>;
}

type Handler<D> = Box<dyn AccountHandler<Data = D> + Send + Sync>;

/// Basic account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Address identifier for the account.
    ///
    /// This corresponds to the address of the signing key
    /// for the account.
    address: Address,
    /// User label for the account.
    ///
    /// This is the name given to the identity vault.
    label: String,
}

impl AccountInfo {
    /// Create new account information.
    pub fn new(label: String, address: Address) -> Self {
        Self { label, address }
    }

    /// Get the address of this account.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the label of this account.
    pub fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

impl From<&AccountInfo> for AccountRef {
    fn from(value: &AccountInfo) -> Self {
        AccountRef::Address(*value.address())
    }
}

impl From<AccountInfo> for AccountRef {
    fn from(value: AccountInfo) -> Self {
        (&value).into()
    }
}

/// Reference to an account using an address or a named label.
#[derive(Debug, Clone)]
pub enum AccountRef {
    /// Account identifier.
    Address(Address),
    /// Account label.
    Name(String),
}

impl fmt::Display for AccountRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(address) => write!(f, "{}", address),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for AccountRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(address) = s.parse::<Address>() {
            Ok(Self::Address(address))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

/// Read-only view created from a specific event log commit.
pub struct DetachedView {
    keeper: Gatekeeper,
    index: Arc<RwLock<SearchIndex>>,
}

impl DetachedView {
    /// Read-only access to the folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Search index for the detached view.
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.index)
    }
}

/// Options used when accessing account data.
#[derive(Default)]
pub struct AccessOptions {
    /// Target folder for the operation.
    ///
    /// If no target folder is given the current open folder
    /// will be used. When no folder is open and the target
    /// folder is not given an error will be returned.
    pub folder: Option<Summary>,
    /// Channel for file progress operations.
    #[cfg(feature = "files")]
    pub file_progress: Option<mpsc::Sender<FileProgress>>,
}

impl From<Summary> for AccessOptions {
    fn from(value: Summary) -> Self {
        Self {
            folder: Some(value),
            #[cfg(feature = "files")]
            file_progress: None,
        }
    }
}

/// Data about an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// Main account information.
    #[serde(flatten)]
    pub account: AccountInfo,
    /// AGE identity public recipient.
    pub identity: String,
    /// Account folders.
    pub folders: Vec<Summary>,
    /*
    #[cfg(feature = "device")]
    /// Address of the device public key.
    pub device_address: String,
    */
}

/// Account information when signed in.
pub(super) struct Authenticated {
    /// Authenticated user.
    user: Identity,

    /// Storage provider.
    storage: Arc<RwLock<FolderStorage>>,

    /// Account event log.
    account_log: Arc<RwLock<AccountEventLog>>,

    /// File event log.
    #[cfg(feature = "files")]
    pub(super) file_log: Arc<RwLock<FileEventLog>>,
}

/// User account backed by the filesystem.
///
/// Many functions require that the account is authenticated and will
/// return [Error::NotAuthenticated] if the account is not authenticated
/// to authenticate a user call [Account::sign_in].
///
/// For functions that return a [CommitState] it represents
/// the state *before* any changes were made. If a `handler`
/// has been assigned the `handler` may alter the [CommitState]
/// by returning a new state after changes from a remote server have
/// been applied.
pub struct Account<D> {
    /// Account address.
    address: Address,

    /// Account information after a successful
    /// sign in.
    pub(super) authenticated: Option<Authenticated>,

    /// Storage paths.
    pub(super) paths: Arc<UserPaths>,

    /// Audit log for this provider.
    audit_log: Arc<RwLock<AuditLogFile>>,

    /// Hook called before making local changes.
    ///
    /// Allows network aware accounts to sync
    /// before changes are applied to the local
    /// storage.
    handler: Option<Handler<D>>,
}

impl<D> Account<D> {
    /// List account information for the identity vaults.
    pub async fn list_accounts(
        paths: Option<&UserPaths>,
    ) -> Result<Vec<AccountInfo>> {
        let mut keys = Vec::new();
        let paths = if let Some(paths) = paths {
            paths.clone()
        } else {
            UserPaths::new_global(UserPaths::data_dir()?)
        };

        let mut dir = vfs::read_dir(paths.identity_dir()).await?;

        while let Some(entry) = dir.next_entry().await? {
            if let (Some(extension), Some(file_stem)) =
                (entry.path().extension(), entry.path().file_stem())
            {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    keys.push(AccountInfo {
                        address: file_stem.to_string_lossy().parse()?,
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)
    }

    /// Find and load a vault.
    pub async fn load_local_vault(
        paths: &UserPaths,
        id: &VaultId,
        include_system: bool,
    ) -> Result<(Vault, PathBuf)> {
        let folders = Self::list_local_folders(paths, include_system).await?;
        let (_summary, path) = folders
            .into_iter()
            .find(|(s, _)| s.id() == id)
            .ok_or_else(|| Error::NoVaultFile(id.to_string()))?;
        let buffer = vfs::read(&path).await?;
        let vault: Vault = decode(&buffer).await?;
        Ok((vault, path))
    }

    /// List the folders in an account by inspecting
    /// the vault files in the vaults directory.
    pub async fn list_local_folders(
        paths: &UserPaths,
        include_system: bool,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = paths.vaults_dir();

        let mut vaults = Vec::new();
        let mut dir = vfs::read_dir(vaults_dir).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let Some(extension) = entry.path().extension() {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    if !include_system && summary.flags().is_system() {
                        continue;
                    }
                    vaults.push((summary, entry.path().to_path_buf()));
                }
            }
        }
        Ok(vaults)
    }

    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
        handler: Option<Handler<D>>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            UserPaths::data_dir()?
        };

        let paths = UserPaths::new_global(data_dir);
        let audit_log = Arc::new(RwLock::new(
            AuditLogFile::new(paths.audit_file()).await?,
        ));

        Ok(Self {
            address,
            paths: Arc::new(paths),
            authenticated: None,
            audit_log,
            handler,
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
        handler: Option<Handler<D>>,
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
            handler,
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
        handler: Option<Handler<D>>,
    ) -> Result<(Self, NewAccount)> {
        let span = span!(Level::DEBUG, "new_account");
        let _enter = span.enter();

        let account_builder = builder(AccountBuilder::new(
            account_name,
            passphrase.clone(),
            data_dir.clone(),
        ));
        let new_account = account_builder.finish().await?;

        tracing::debug!(address = %new_account.address, "created account");

        // Must import the new account before signing in
        let signer = new_account.user.identity()?.signer().clone();
        let address = signer.address()?;
        let mut storage =
            FolderStorage::new(address.to_string(), data_dir.clone()).await?;

        tracing::debug!("prepared storage provider");

        let events = storage.import_new_account(&new_account).await?;

        tracing::debug!("imported new account");

        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            UserPaths::data_dir()?
        };

        let paths = UserPaths::new_global(data_dir);
        let audit_log = Arc::new(RwLock::new(
            AuditLogFile::new(paths.audit_file()).await?,
        ));

        let owner = Self {
            address,
            paths: Arc::new(paths),
            authenticated: None,
            audit_log,
            handler,
        };

        let mut audit_events = Vec::new();
        for event in events {
            let audit_event: AuditEvent =
                (new_account.address(), &event).into();
            audit_events.push(audit_event);
        }
        owner.append_audit_logs(audit_events).await?;

        Ok((owner, new_account))
    }

    /// Authenticated user information.
    pub fn user(&self) -> Result<&Identity> {
        self.authenticated
            .as_ref()
            .map(|a| &a.user)
            .ok_or(Error::NotAuthenticated)
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> Result<&mut Identity> {
        self.authenticated
            .as_mut()
            .map(|a| &mut a.user)
            .ok_or(Error::NotAuthenticated)
    }

    /// Storage provider.
    pub fn storage(&self) -> Result<Arc<RwLock<FolderStorage>>> {
        let auth =
            self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        Ok(Arc::clone(&auth.storage))
    }

    /// Account address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get access to an account by signing in.
    pub async fn sign_in(&mut self, passphrase: SecretString) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_in");
        let _enter = span.enter();

        let address = &self.address;
        let data_dir = self.paths().documents_dir().clone();

        tracing::debug!(address = %address);

        // Ensure all paths before sign_in
        let paths = UserPaths::ensure_paths(
            address.to_string(),
            Some(data_dir.clone()),
        )
        .await?;

        tracing::debug!(data_dir = ?paths.documents_dir());

        let mut user = Identity::new(paths.clone());
        user.sign_in(self.address(), passphrase).await?;
        tracing::debug!("sign in success");

        // Signing key for the storage provider
        let signer = user.identity()?.signer().clone();
        let storage =
            FolderStorage::new(signer.address()?.to_string(), Some(data_dir))
                .await?;
        self.paths = storage.paths();

        let account_log =
            self.initialize_account_log(&self.paths, &user).await?;

        #[cfg(feature = "files")]
        let file_log = self.initialize_file_log(&self.paths).await?;

        self.authenticated = Some(Authenticated {
            user,
            storage: Arc::new(RwLock::new(storage)),
            account_log,
            #[cfg(feature = "files")]
            file_log,
        });

        // Load vaults into memory and initialize folder
        // event log commit trees
        self.load_folders().await?;

        Ok(())
    }

    async fn initialize_account_log(
        &self,
        paths: &UserPaths,
        user: &Identity,
    ) -> Result<Arc<RwLock<AccountEventLog>>> {
        let span = span!(Level::DEBUG, "init_account_log");
        let _enter = span.enter();

        let log_file = paths.account_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = AccountEventLog::new_account(log_file).await?;

        tracing::debug!(needs_init = %needs_init);

        // If the account event log does not already exist
        // we initialize it from the current state on disc
        // adding create folder events for every folder that
        // already exists
        if needs_init {
            let folders: Vec<Summary> =
                Self::list_local_folders(paths, false)
                    .await?
                    .into_iter()
                    .map(|(s, _)| s)
                    .collect();

            let mut events = Vec::new();

            for folder in folders {
                let secure_access_key =
                    user.secure_access_key(folder.id()).await?;
                events.push(AccountEvent::CreateFolder(
                    folder.into(),
                    secure_access_key,
                ));
            }

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(Arc::new(RwLock::new(event_log)))
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(
        &self,
        paths: &UserPaths,
    ) -> Result<Arc<RwLock<FileEventLog>>> {
        let span = span!(Level::DEBUG, "init_file_log");
        let _enter = span.enter();

        let log_file = paths.file_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = FileEventLog::new_file(log_file).await?;

        tracing::debug!(needs_init = %needs_init);

        if needs_init {
            let files = super::files::list_external_files(paths).await?;
            let events: Vec<FileEvent> =
                files.into_iter().map(|f| f.into()).collect();

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(Arc::new(RwLock::new(event_log)))
    }

    /// Determine if the account is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated.is_some()
    }

    /// User storage paths.
    pub fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// Append to the audit log.
    pub async fn append_audit_logs(
        &self,
        events: Vec<AuditEvent>,
    ) -> Result<()> {
        let mut writer = self.audit_log.write().await;
        writer.append_audit_events(events).await?;
        Ok(())
    }

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to authenticate other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the master password for this account.
    pub async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let identity_path = reader.paths().identity_vault();
        Ok(vfs::read(identity_path).await?)
    }

    /// Compute the account statistics.
    ///
    /// If the account is not authenticated returns
    /// a default statistics object (all values will be zero).
    pub async fn statistics(&self) -> AccountStatistics {
        if let Some(auth) = &self.authenticated {
            let storage = self.storage().unwrap();
            let reader = storage.read().await;
            let search_index = reader.index().search();
            let index = search_index.read().await;
            let statistics = index.statistics();
            let count = statistics.count();

            let documents: usize = count.vaults().values().sum();
            let mut folders = Vec::new();
            let mut types = HashMap::new();

            for (id, v) in count.vaults() {
                if let Some(summary) = self.find(|s| s.id() == id).await {
                    folders.push((summary, *v));
                }
            }

            for (k, v) in count.kinds() {
                if let Ok(kind) = SecretType::try_from(*k) {
                    types.insert(kind, *v);
                }
            }

            AccountStatistics {
                documents,
                folders,
                types,
                tags: count.tags().clone(),
                favorites: count.favorites(),
            }
        } else {
            Default::default()
        }
    }

    /// Account data.
    pub async fn account_data(&self) -> Result<AccountData> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let user = self.user()?;
        Ok(AccountData {
            account: user.account()?.clone(),
            identity: user.identity()?.recipient().to_string(),
            folders: reader.folders().to_vec(),
        })
    }

    /// Verify an access key for this account.
    ///
    /// If the account is not authenticated this returns false.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(auth) = &self.authenticated {
            auth.user.verify(key).await
        } else {
            false
        }
    }

    /// Delete the account for this user and sign out.
    pub async fn delete_account(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "delete_account");
        let _enter = span.enter();

        let paths = self.paths().clone();
        let event = self.user_mut()?.delete_account(&paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;
        self.sign_out().await?;
        Ok(())
    }

    /// Rename this account.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        let paths = self.paths().clone();
        Ok(self
            .user_mut()?
            .rename_account(&paths, account_name)
            .await?)
    }

    /// Try to find a folder using a predicate.
    pub async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool,
    {
        if let Some(auth) = &self.authenticated {
            let reader = auth.storage.read().await;
            reader.find(predicate).cloned()
        } else {
            None
        }
    }

    /// Find the default folder.
    pub async fn default_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_default()).await
    }

    /// Find the authenticator folder.
    pub async fn authenticator_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_authenticator()).await
    }

    /// Find the contacts folder.
    pub async fn contacts_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_contact()).await
    }

    /// Find the archive folder.
    pub async fn archive_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_archive()).await
    }

    /// Load folders into memory.
    ///
    /// This method is automatically called on sign in to
    /// prepare the in-memory vaults but can be explicitly
    /// called to reload the data from disc.
    pub async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        tracing::debug!("load folders");
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        Ok(writer.load_vaults().await?.to_vec())
    }

    /// List in-memory folders managed by this account.
    pub async fn list_folders(&self) -> Result<Vec<Summary>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        Ok(reader.folders().to_vec())
    }

    /// Sign out of the account.
    pub async fn sign_out(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());

        tracing::debug!("close current open vault");
        // Close the currently open vaul in the local storage
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.close_vault();

        tracing::debug!("clear search index");
        // Remove the search index
        writer.index_mut().clear().await;

        tracing::debug!("sign out user identity");
        // Forget private identity information
        self.user_mut()?.sign_out().await?;

        tracing::debug!("remove authenticated state");
        self.authenticated = None;

        Ok(())
    }

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Event, CommitState, SecureAccessKey)> {
        let passphrase = self.user()?.generate_folder_password()?;
        let key: AccessKey = passphrase.into();
        let (buffer, _, summary) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.create_vault(name, Some(key.clone())).await?
        };

        // Must save the password before getting the secure access key
        self.user_mut()?
            .save_folder_password(summary.id(), key)
            .await?;

        let secure_key = self.user()?.secure_access_key(summary.id()).await?;

        let account_event =
            AccountEvent::CreateFolder(*summary.id(), secure_key.clone());

        let options = AccessOptions {
            folder: Some(summary),
            ..Default::default()
        };

        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        if let Some(auth) = self.authenticated.as_mut() {
            let mut account_log = auth.account_log.write().await;
            account_log.append_event(&account_event).await?;
        }

        let audit_event: AuditEvent =
            (self.address(), &Event::Account(account_event)).into();
        self.append_audit_logs(vec![audit_event]).await?;

        let event =
            Event::Write(*summary.id(), WriteEvent::CreateVault(buffer));

        Ok((summary, event, commit_state, secure_key))
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<(Event, CommitState)> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.remove_vault(&summary).await?
        };
        self.user_mut()?
            .remove_folder_password(summary.id())
            .await?;

        #[cfg(feature = "files")]
        self.delete_folder_files(&summary).await?;

        let account_event = AccountEvent::DeleteFolder(*summary.id());
        if let Some(auth) = self.authenticated.as_mut() {
            let mut account_log = auth.account_log.write().await;
            account_log.append_event(&account_event).await?;
        }

        let audit_event: AuditEvent =
            (self.address(), &Event::Account(account_event.clone())).into();
        self.append_audit_logs(vec![audit_event]).await?;

        Ok((Event::Account(account_event), commit_state))
    }

    /// Rename a folder.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<(Event, CommitState)> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        // Update the provider
        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.set_vault_name(&summary, &name).await?
        };

        let event = Event::Write(*summary.id(), event);
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        Ok((event, commit_state))
    }

    /// Export a folder as a vault file.
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let buffer = self
            .change_folder_password(summary.id(), new_key.clone())
            .await?;

        if save_key {
            let default_summary = self
                .default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?;

            let _passphrase = self
                .user()?
                .find_folder_password(default_summary.id())
                .await?;

            let timestamp: Timestamp = Default::default();
            let label = format!(
                "Exported folder {}.vault ({})",
                summary.id(),
                timestamp.to_rfc3339()?
            );
            let secret = Secret::Account {
                account: format!("{}.vault", summary.id()),
                url: None,
                password: new_key.into(),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());

            let (vault, _) = Self::load_local_vault(
                &self.paths,
                default_summary.id(),
                false,
            )
            .await?;

            self.add_secret(
                meta,
                secret,
                vault.summary().clone().into(),
                false,
            )
            .await?;
        }

        vfs::write(path, buffer).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportVault,
            self.address().clone(),
            Some(AuditData::Vault(*summary.id())),
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Export a vault by changing the vault passphrase and
    /// converting it to a buffer.
    ///
    /// The identity vault must be unlocked so we can retrieve
    /// the passphrase for the target vault.
    async fn change_folder_password(
        &self,
        vault_id: &VaultId,
        new_passphrase: AccessKey,
    ) -> Result<Vec<u8>> {
        use crate::passwd::ChangePassword;
        let paths = self.paths().clone();
        // Get the current vault passphrase from the identity vault
        let current_passphrase =
            self.user()?.find_folder_password(vault_id).await?;

        // Find the local vault for the account
        let (vault, _) =
            Self::load_local_vault(&paths, vault_id, false).await?;

        // Change the password before exporting
        let (_, vault, _) = ChangePassword::new(
            &vault,
            current_passphrase,
            new_passphrase,
            None,
        )
        .build()
        .await?;

        encode(&vault).await
    }

    /// Import a folder from a vault file.
    pub async fn import_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event, CommitState)> {
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    /// Import a folder from a vault buffer.
    pub async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event, CommitState)> {
        let mut vault: Vault = decode(buffer.as_ref()).await?;

        // Need to verify the passphrase
        vault.verify(&key).await?;

        // Check for existing identifier
        let vaults = Self::list_local_folders(&self.paths, false).await?;
        let existing_id =
            vaults.iter().find(|(s, _)| s.id() == vault.summary().id());

        let default_vault =
            vaults.iter().find(|(s, _)| s.flags().is_default());

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            vault.rotate_identifier();
            true
        } else {
            false
        };

        let existing_name = vaults
            .iter()
            .find(|(s, _)| s.name() == vault.summary().name());

        let has_name_changed = if existing_name.is_some() && !overwrite {
            let name = format!(
                "{} ({})",
                vault.summary().name(),
                vault.summary().id()
            );
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
            vault.set_default_flag(false);
        }

        let buffer: Cow<[u8]> =
            if has_id_changed || has_name_changed || remove_default_flag {
                // Need to update the buffer as we changed the data
                Cow::Owned(encode(&vault).await?)
            } else {
                Cow::Borrowed(buffer.as_ref())
            };

        // Import the vault
        let (event, summary) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.import_vault(buffer.as_ref(), Some(&key)).await?
        };

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            self.user_mut()?
                .remove_folder_password(summary.id())
                .await?;
        }

        self.user_mut()?
            .save_folder_password(summary.id(), key.clone())
            .await?;

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            {
                let storage = self.storage()?;
                let mut writer = storage.write().await;
                let is_current = if let Some(current) = writer.current() {
                    current.id() == summary.id()
                } else {
                    false
                };

                if is_current {
                    writer.close_vault();
                }
            }
        }

        let event = Event::Write(*summary.id(), event);
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        Ok((summary, event, commit_state))
    }

    /// Open a vault.
    pub async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        self.open_vault(summary, true).await
    }

    pub(crate) async fn open_vault(
        &mut self,
        summary: &Summary,
        audit: bool,
    ) -> Result<()> {
        // Bail early if the folder is already open
        // as opening a vault is an expensive operation
        {
            let storage = self.storage()?;
            let reader = storage.read().await;
            if let Some(current) = reader.current() {
                if current.id() == summary.id() {
                    return Ok(());
                }
            }
        }

        let passphrase =
            self.user()?.find_folder_password(summary.id()).await?;

        //let index = Arc::clone(&self.index()?.search_index);

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            let key: AccessKey = passphrase.into();
            writer.open_vault(summary, &key).await?
        };

        let event = Event::Read(*summary.id(), event);

        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Helper to get all the state information needed
    /// before calling sync methods.
    ///
    /// Computes the target folder that will be used, the last commit
    /// hash and the proof for the current head of the events log.
    async fn compute_folder_state(
        &self,
        options: &AccessOptions,
        apply_changes: bool,
    ) -> Result<(Summary, CommitState)> {
        let (folder, last_commit, mut commit_proof) = {
            let storage = self.storage()?;
            let reader = storage.read().await;
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

        let mut last_commit = last_commit.ok_or(Error::NoRootCommit)?;

        if apply_changes {
            let storage = self.storage()?;
            if let Some(handler) = &self.handler {
                let before_result = handler
                    .before_change(
                        storage,
                        &folder,
                        &(last_commit, commit_proof.clone()),
                    )
                    .await;
                if let Some((commit, proof)) = before_result {
                    last_commit = commit;
                    commit_proof = proof;
                }
            }
        }

        Ok((folder, (last_commit, commit_proof)))
    }

    /// Bulk insert secrets into the currently open folder.
    pub async fn insert(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<Vec<(SecretId, Event, CommitState, Summary)>> {
        let mut results = Vec::new();
        for (meta, secret) in secrets {
            results.push(
                self.create_secret(meta, secret, Default::default()).await?,
            );
        }
        Ok(results)
    }

    /// Create a secret in the current open folder or a specific folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        let (id, event, _) =
            self.add_secret(meta, secret, options, true).await?;

        Ok((id, event, commit_state, folder))
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        mut options: AccessOptions,
        audit: bool,
    ) -> Result<(SecretId, Event, Summary)> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            options
                .folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let id = SecretId::new_v4();

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer
                .create_secret(id, meta.clone(), secret.clone())
                .await?
        };

        let secret_data = SecretRow::new(id, meta, secret);
        let current_folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            reader
                .current()
                .as_ref()
                .map(|g| g.summary().clone())
                .ok_or(Error::NoOpenFolder)?
        };

        #[cfg(feature = "files")]
        {
            let events = self
                .create_files(
                    &current_folder,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;
            self.append_file_mutation_events(&events).await?;
        }

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok((id, event, folder))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.get_secret(secret_id, folder, true).await
    }

    /// Get a secret in the current open folder and
    /// optionally append to the audit log.
    ///
    /// Some internal operations needn't generate extra
    /// audit log records.
    pub(crate) async fn get_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<(SecretRow, ReadEvent)> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let (meta, secret, read_event) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.read_secret(secret_id).await?
        };

        if audit {
            let event = Event::Read(*folder.id(), read_event.clone());
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok((SecretRow::new(*secret_id, meta, secret), read_event))
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
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(
            secret_id,
            meta,
            Some(secret),
            options,
            destination,
        )
        .await
    }

    /// Update a secret in the current open folder or a specific folder.
    pub async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        mut options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        let (old_secret_data, _) =
            self.get_secret(secret_id, None, false).await?;

        let secret_data = if let Some(secret) = secret {
            SecretRow::new(*secret_id, meta, secret)
        } else {
            let mut secret_data = old_secret_data.clone();
            secret_data.meta = meta;
            secret_data
        };

        let event = self
            .write_secret(secret_id, secret_data.clone(), None, true)
            .await?;

        // Must update the files before moving so checksums are correct
        #[cfg(feature = "files")]
        {
            let events = self
                .update_files(
                    &folder,
                    &folder,
                    &old_secret_data,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;
            self.append_file_mutation_events(&events).await?;
        }

        let id = if let Some(to) = destination.as_ref() {
            let (new_id, _) =
                self.mv_secret(secret_id, &folder, to, options).await?;
            new_id
        } else {
            *secret_id
        };

        Ok((id, event, commit_state, folder))
    }

    /// Write a secret in the current open folder or a specific folder.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    pub(crate) async fn write_secret(
        &mut self,
        secret_id: &SecretId,
        secret_data: SecretRow,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<Event> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };
        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = secret_data.secret() {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.update_secret(secret_id, secret_data).await?
        };

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok(event)
    }

    /// Move a secret between folders.
    pub async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        mut options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        self.open_vault(from, false).await?;
        let (secret_data, read_event) =
            self.get_secret(secret_id, None, false).await?;
        let move_secret_data = secret_data.clone();

        self.open_vault(to, false).await?;
        let (new_id, create_event, _) = self
            .add_secret(
                secret_data.meta,
                secret_data.secret,
                Default::default(),
                false,
            )
            .await?;
        self.open_vault(from, false).await?;

        // Note that we call `remove_secret()` and not `delete_secret()`
        // as we need the original external files for the
        // move_files operation.
        let delete_event = self.remove_secret(secret_id, None, false).await?;

        #[cfg(feature = "files")]
        {
            let events = self
                .move_files(
                    &move_secret_data,
                    from.id(),
                    to.id(),
                    secret_id,
                    &new_id,
                    None,
                    &mut options.file_progress,
                )
                .await?;
            self.append_file_mutation_events(&events).await?;
        }

        let (_, create_event) = create_event.try_into()?;
        let (_, delete_event) = delete_event.try_into()?;

        let event = Event::MoveSecret(read_event, create_event, delete_event);

        let audit_event = AuditEvent::new(
            EventKind::MoveSecret,
            self.address().clone(),
            Some(AuditData::MoveSecret {
                from_vault_id: *from.id(),
                to_vault_id: *to.id(),
                from_secret_id: *secret_id,
                to_secret_id: new_id.clone(),
            }),
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok((new_id, event))
    }

    /// Delete a secret and remove any external files.
    pub async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        mut options: AccessOptions,
    ) -> Result<(Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        let (secret_data, _) =
            self.get_secret(secret_id, None, false).await?;
        let event = self.remove_secret(secret_id, None, true).await?;

        #[cfg(feature = "files")]
        {
            let events = self
                .delete_files(
                    &folder,
                    &secret_data,
                    None,
                    &mut options.file_progress,
                )
                .await?;
            self.append_file_mutation_events(&events).await?;
        }

        Ok((event, commit_state, folder))
    }

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    pub(crate) async fn remove_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<Event> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.delete_secret(secret_id).await?
        };

        /*
        {
            let search = self.index()?.search();
            let mut writer = search.write().await;
            writer.remove(folder.id(), secret_id);
        }
        */

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }
        Ok(event)
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
        if from.flags().is_archive() {
            return Err(Error::AlreadyArchived);
        }
        self.open_folder(from).await?;
        let to = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        self.move_secret(secret_id, from, &to, options).await
    }

    /// Move a secret out of the archive.
    ///
    /// The secret must be inside a folder with the archive flag set
    pub async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(Summary, SecretId, Event)> {
        if !from.flags().is_archive() {
            return Err(Error::NotArchived);
        }
        self.open_folder(from).await?;
        let mut to = self
            .default_folder()
            .await
            .ok_or_else(|| Error::NoDefaultFolder)?;
        let authenticator = self.authenticator_folder().await;
        let contacts = self.contacts_folder().await;
        if secret_meta.kind() == &SecretType::Totp && authenticator.is_some()
        {
            to = authenticator.unwrap();
        } else if secret_meta.kind() == &SecretType::Contact
            && contacts.is_some()
        {
            to = contacts.unwrap();
        }
        let (id, event) =
            self.move_secret(secret_id, from, &to, options).await?;
        Ok((to, id, event))
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let keys = self.folder_keys().await?;
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.initialize_search_index(&keys).await
    }

    /// Build the search index for all folders.
    pub(crate) async fn build_search_index(
        &mut self,
    ) -> Result<DocumentCount> {
        let keys = self.folder_keys().await?;
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.build_search_index(&keys).await
    }

    /// Get the access keys for all folders.
    async fn folder_keys(&self) -> Result<FolderKeys> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let folders = reader.folders();
        let mut keys = HashMap::new();
        for folder in folders {
            keys.insert(
                folder.clone(),
                self.user()?.find_folder_password(folder.id()).await?,
            );
        }
        Ok(FolderKeys(keys))
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
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));

        let storage = self.storage()?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;

        let passphrase =
            self.user()?.find_folder_password(summary.id()).await?;

        let vault = EventReducer::new_until_commit(commit)
            .reduce(log_file)
            .await?
            .build()
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = passphrase.into();
        keeper.unlock(&key).await?;

        {
            let mut index = search_index.write().await;
            index.add_folder(&keeper).await?;
        }

        Ok(DetachedView {
            keeper,
            index: search_index,
        })
    }

    /// Get the root commit hash for a folder.
    pub async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        Ok(log_file
            .tree()
            .root()
            .map(CommitHash)
            .ok_or_else(|| Error::NoRootCommit)?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    pub async fn commit_state(
        &self,
        summary: &Summary,
    ) -> Result<CommitState> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        Ok(log_file.commit_state().await?)
    }

    /// Compact an event log file.
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (old_size, new_size) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.compact(&summary).await?
        };

        let auth =
            self.authenticated.as_mut().ok_or(Error::NotAuthenticated)?;
        let event = AccountEvent::CompactFolder(*summary.id());
        let mut account_log = auth.account_log.write().await;
        account_log.apply(vec![&event]).await?;
        Ok((old_size, new_size))
    }
}
