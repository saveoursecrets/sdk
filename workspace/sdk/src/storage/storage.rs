//! Storage backed by the filesystem.
use crate::{
    commit::{CommitHash, CommitState, CommitTree},
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, AuditEvent, Event, EventKind,
        EventReducer, FolderEventLog, ReadEvent, WriteEvent,
    },
    identity::FolderKeys,
    passwd::{diceware::generate_passphrase, ChangePassword},
    signer::ecdsa::Address,
    storage::AccessOptions,
    storage::AccountPack,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        FolderRef, Gatekeeper, Header, Summary, Vault, VaultAccess,
        VaultBuilder, VaultCommit, VaultFlags, VaultId, VaultMeta,
        VaultWriter,
    },
    vfs, Error, Paths, Result, Timestamp,
};

use secrecy::SecretString;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};

#[cfg(feature = "archive")]
use crate::account::archive::RestoreTargets;

#[cfg(feature = "files")]
use crate::events::{FileEvent, FileEventLog};

#[cfg(feature = "search")]
use crate::storage::search::{AccountSearch, DocumentCount, SearchIndex};

/// Folder is a combined vault and event log.
pub struct Folder {
    pub(crate) keeper: Gatekeeper,
    events: Option<Arc<RwLock<FolderEventLog>>>,
}

impl Folder {
    /// Create a new folder.
    fn new(keeper: Gatekeeper, events: Option<FolderEventLog>) -> Self {
        Self {
            keeper,
            events: events.map(|e| Arc::new(RwLock::new(e))),
        }
    }

    /// Create a new folder from a vault buffer.
    ///
    /// Changes are not mirrored to disc and events are not logged.
    pub async fn new_buffer(buffer: impl AsRef<[u8]>) -> Result<Self> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let keeper = Gatekeeper::new(vault);
        Ok(Self::new(keeper, None))
    }

    /// Create a new folder from a vault file.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    pub async fn new_file(path: impl AsRef<Path>) -> Result<Self> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log = FolderEventLog::new_folder(events_path).await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        let vault = if needs_init {
            // For the client-side we must split the events
            // out but keep the existing vault data (not the head-only)
            // version so that the event log here will match what the
            // server will have when an account is first synced
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            let (_, events) = EventReducer::split(vault.clone()).await?;
            event_log.apply(events.iter().collect()).await?;
            vault
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            vault
        };

        let vault_file = VaultWriter::open(path.as_ref()).await?;
        let mirror = VaultWriter::new(path.as_ref(), vault_file)?;
        let keeper = Gatekeeper::new_mirror(vault, mirror);

        Ok(Self::new(keeper, Some(event_log)))
    }

    /// Load an identity vault event log from the given paths.
    pub async fn new_event_log(
        paths: &Paths,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let mut event_log =
            FolderEventLog::new_folder(paths.identity_events()).await?;
        event_log.load_tree().await?;
        Ok(Arc::new(RwLock::new(event_log)))
    }

    /// Clone of the event log.
    pub fn event_log(&self) -> Option<Arc<RwLock<FolderEventLog>>> {
        self.events.clone()
    }

    /// Folder identifier.
    pub fn id(&self) -> &VaultId {
        self.keeper.id()
    }

    /// Gatekeeper for this folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Unlock using the folder access key.
    pub async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        self.keeper.unlock(key).await
    }

    /// Lock the folder.
    pub fn lock(&mut self) {
        self.keeper.lock();
    }

    /// Create a secret.
    pub async fn create(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        let event = self.keeper.create(secret_data).await?;
        if let Some(events) = self.events.as_mut() {
            let mut events = events.write().await;
            events.apply(vec![&event]).await?;
        }
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        self.keeper.read(id).await
    }

    /// Update a secret.
    pub async fn update(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) =
            self.keeper.update(id, secret_meta, secret).await?
        {
            if let Some(events) = self.events.as_mut() {
                let mut events = events.write().await;
                events.apply(vec![&event]).await?;
            }
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Delete a secret and it's meta data.
    pub async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) = self.keeper.delete(id).await? {
            if let Some(events) = self.events.as_mut() {
                let mut events = events.write().await;
                events.apply(vec![&event]).await?;
            }
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}

/// Manages multiple folders loaded into memory and mirrored to disc.
pub struct Storage {
    /// Address of the account owner.
    pub(super) address: Address,

    /// State of this storage.
    pub(super) state: LocalState,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

    /// Search index.
    #[cfg(feature = "search")]
    pub(super) index: Option<AccountSearch>,

    /// Identity vault event log.
    ///
    /// This is a clone of the main identity vault
    /// event log and is defined here so we can
    /// get the commit state for synchronization.
    pub(super) identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub(super) account_log: Arc<RwLock<AccountEventLog>>,

    /// Folder event logs.
    pub(super) cache: HashMap<VaultId, FolderEventLog>,

    /// File event log.
    #[cfg(feature = "files")]
    pub(super) file_log: FileEventLog,

    /// Password for file encryption.
    #[cfg(feature = "files")]
    pub(super) file_password: Option<SecretString>,
}

impl Storage {
    /// Create folder storage for client-side access.
    pub async fn new_client(
        address: Address,
        data_dir: Option<PathBuf>,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir().map_err(|_| Error::NoCache)?
        };

        let dirs = Paths::new(data_dir, address.to_string());
        Self::new_paths(Arc::new(dirs), address, identity_log, true, false)
            .await
    }

    /// Create folder storage for server-side access.
    pub async fn new_server(
        address: Address,
        data_dir: Option<PathBuf>,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir().map_err(|_| Error::NoCache)?
        };

        let dirs = Paths::new_server(data_dir, address.to_string());
        Self::new_paths(Arc::new(dirs), address, identity_log, true, true)
            .await
    }

    /// Create new storage backed by files on disc.
    async fn new_paths(
        paths: Arc<Paths>,
        address: Address,
        identity_log: Arc<RwLock<FolderEventLog>>,
        mirror: bool,
        head_only: bool,
    ) -> Result<Storage> {
        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            ));
        }

        paths.ensure().await?;

        let log_file = paths.account_events();
        let mut event_log = AccountEventLog::new_account(log_file).await?;
        event_log.load_tree().await?;
        let account_log = Arc::new(RwLock::new(event_log));

        #[cfg(feature = "files")]
        let file_log = Self::initialize_file_log(&*paths).await?;

        Ok(Self {
            address,
            state: LocalState::new(mirror, head_only),
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            #[cfg(feature = "search")]
            index: Some(AccountSearch::new()),
            #[cfg(feature = "files")]
            file_log,
            #[cfg(feature = "files")]
            file_password: None,
        })
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Access to the identity log.
    pub fn identity_log(&self) -> Arc<RwLock<FolderEventLog>> {
        Arc::clone(&self.identity_log)
    }

    /// Access to the account log.
    pub fn account_log(&self) -> Arc<RwLock<AccountEventLog>> {
        Arc::clone(&self.account_log)
    }

    /// Set the password for file encryption.
    #[cfg(feature = "files")]
    pub fn set_file_password(&mut self, file_password: Option<SecretString>) {
        self.file_password = file_password;
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(paths: &Paths) -> Result<FileEventLog> {
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

        Ok(event_log)
    }

    /// Search index reference.
    #[cfg(feature = "search")]
    pub fn index(&self) -> Result<&AccountSearch> {
        self.index.as_ref().ok_or(Error::NoSearchIndex)
    }

    /// Mutable search index reference.
    #[cfg(feature = "search")]
    pub fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        self.index.as_mut().ok_or(Error::NoSearchIndex)
    }

    /// Get the event log cache.
    pub fn cache(&self) -> &HashMap<VaultId, FolderEventLog> {
        &self.cache
    }

    /// Get the mutable event log cache.
    pub fn cache_mut(&mut self) -> &mut HashMap<VaultId, FolderEventLog> {
        &mut self.cache
    }

    /// Find a summary in this storage.
    pub fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        self.state.find_vault(vault)
    }

    /// Find a summary in this storage.
    pub fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.state.find(predicate)
    }

    /// Get the computed storage directories for the provider.
    pub fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    pub(crate) async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        // Find the id of an archive folder
        let summaries = {
            let summaries = self.list_folders();
            let mut archive: Option<VaultId> = None;
            for summary in summaries {
                if summary.flags().is_archive() {
                    archive = Some(*summary.id());
                    break;
                }
            }
            if let Some(index) = &self.index {
                let mut writer = index.search_index.write().await;
                writer.set_archive_id(archive);
            }
            summaries
        };
        let folders = summaries.to_vec();
        Ok((self.build_search_index(keys).await?, folders))
    }

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    pub(crate) async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        {
            let index = self.index.as_ref().ok_or(Error::NoSearchIndex)?;
            let search_index = index.search();
            let mut writer = search_index.write().await;

            // Clear search index first
            writer.remove_all();

            for (summary, key) in &keys.0 {
                // Must open the vault so the provider state unlocks
                // the vault
                self.open_vault(summary, key).await?;

                let folder = self.current().unwrap();
                writer.add_folder(folder).await?;

                // Close the vault as we are done for now
                self.close_vault();
            }
        }

        let count = if let Some(index) = &self.index {
            index.document_count().await
        } else {
            Default::default()
        };

        Ok(count)
    }

    /// Load a vault, unlock it and set it as the current vault.
    pub(crate) async fn open_vault(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<ReadEvent> {
        let vault_path = self.paths.vault_path(summary.id());
        let vault = if self.state.mirror() {
            if !vfs::try_exists(&vault_path).await? {
                let vault = self.reduce_event_log(summary).await?;
                let buffer = encode(&vault).await?;
                self.write_vault_file(summary.id(), &buffer).await?;
                vault
            } else {
                let buffer = vfs::read(&vault_path).await?;
                let vault: Vault = decode(&buffer).await?;
                vault
            }
        } else {
            self.reduce_event_log(summary).await?
        };

        self.state.open_vault(key, vault, vault_path).await?;
        Ok(ReadEvent::ReadVault)
    }

    /// Create the data for a new account.
    pub async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        let create_account = Event::CreateAccount(AuditEvent::new(
            EventKind::CreateAccount,
            self.address.clone(),
            None,
        ));

        let audit_event: AuditEvent =
            (self.address(), &create_account).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        // Import folders
        for folder in &account.folders {
            let buffer = encode(folder).await?;
            let (event, _) = self.import_folder(buffer, None).await?;
            events.push(event);
        }

        events.insert(0, create_account);

        Ok(events)
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    #[cfg(feature = "archive")]
    pub async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
    ) -> Result<()> {
        let RestoreTargets { vaults, .. } = targets;

        // We may be restoring vaults that do not exist
        // so we need to update the cache
        let summaries = vaults
            .iter()
            .map(|(_, v)| v.summary().clone())
            .collect::<Vec<_>>();
        self.load_caches(&summaries).await?;

        for (buffer, vault) in vaults {
            // Prepare a fresh log of event log events
            let mut event_log_events = Vec::new();
            let create_vault = WriteEvent::CreateVault(buffer.clone());
            event_log_events.push(create_vault);

            self.update_vault(vault.summary(), vault, event_log_events)
                .await?;

            // Refresh the in-memory and disc-based mirror
            self.refresh_vault(vault.summary(), None).await?;
        }

        Ok(())
    }

    /// List the folder summaries for this storage.
    pub fn list_folders(&self) -> &[Summary] {
        self.state.summaries()
    }

    /// Reference to the currently open folder.
    pub fn current_folder(&self) -> Option<&Summary> {
        self.current().map(|g| g.summary())
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.state.current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state.current_mut()
    }

    /// Create new event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()> {
        let event_log_path = self.paths.event_log_path(summary.id());
        let mut event_log =
            FolderEventLog::new_folder(&event_log_path).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.clear().await?;

            let (vault, events) = EventReducer::split(vault).await?;
            event_log.apply(events.iter().collect()).await?;

            if self.state.head_only && self.state.mirror {
                let buffer = encode(&vault).await?;
                self.write_vault_file(summary.id(), buffer).await?;
            }
        }
        event_log.load_tree().await?;

        self.cache_mut().insert(*summary.id(), event_log);
        Ok(())
    }

    /// Refresh the in-memory vault from the contents
    /// of the current event log file.
    ///
    /// If a new access key is given and the target
    /// folder is the currently open folder then the
    /// in-memory `Gatekeeper` is updated to use the new
    /// access key.
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_key: Option<&AccessKey>,
    ) -> Result<Vec<u8>> {
        let vault = self.reduce_event_log(summary).await?;

        // Rewrite the on-disc version if we are mirroring
        let buffer = if self.state.mirror() {
            let buffer = encode(&vault).await?;
            self.write_vault_file(summary.id(), &buffer).await?;
            buffer
        } else {
            encode(&vault).await?
        };

        #[cfg(feature = "search")]
        if let Some(index) = &self.index {
            let index = index.search();
            if let Some(keeper) = self.current_mut() {
                if keeper.id() == summary.id() {
                    Self::replace_vault(index, keeper, vault, new_key)
                        .await?;
                }
            }
        }
        Ok(buffer)
    }

    /// Replace a vault in a gatekeeper and update the
    /// search index if the access key for the vault is
    /// available.
    #[cfg(feature = "search")]
    async fn replace_vault(
        index: Arc<RwLock<SearchIndex>>,
        keeper: &mut Gatekeeper,
        vault: Vault,
        new_key: Option<&AccessKey>,
    ) -> Result<()> {
        let existing_keys = vault.keys().collect::<HashSet<_>>();

        keeper.lock();
        keeper.replace_vault(vault.clone()).await?;

        if let Some(key) = new_key {
            keeper.unlock(key).await?;

            let updated_keys = keeper.vault().keys().collect::<HashSet<_>>();
            let mut writer = index.write().await;

            for added_key in updated_keys.difference(&existing_keys) {
                if let Some((meta, secret, _)) = keeper
                    .read(added_key /*, Some(&vault), derived_key*/)
                    .await?
                {
                    writer.add(keeper.id(), added_key, &meta, &secret);
                }
            }

            for deleted_key in existing_keys.difference(&updated_keys) {
                writer.remove(keeper.id(), deleted_key);
            }

            for maybe_updated in updated_keys.union(&existing_keys) {
                if let (
                    Some(VaultCommit(existing_hash, _)),
                    Some(VaultCommit(updated_hash, _)),
                ) = (
                    keeper.vault().get(maybe_updated),
                    vault.get(maybe_updated),
                ) {
                    if existing_hash != updated_hash {
                        if let Some((meta, secret, _)) = keeper
                            .read(
                                maybe_updated,
                                //Some(&vault),
                                //derived_key,
                            )
                            .await?
                        {
                            writer.update(
                                keeper.id(),
                                maybe_updated,
                                &meta,
                                &secret,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Read a vault from the file on disc.
    pub(crate) async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        let buffer = self.read_vault_file(id).await?;
        Ok(decode(&buffer).await?)
    }

    /// Read the buffer for a vault from disc.
    async fn read_vault_file(&self, id: &VaultId) -> Result<Vec<u8>> {
        let vault_path = self.paths.vault_path(id);
        Ok(vfs::read(vault_path).await?)
    }

    /// Write the buffer for a vault to disc.
    async fn write_vault_file(
        &self,
        vault_id: &VaultId,
        buffer: impl AsRef<[u8]>,
    ) -> Result<()> {
        let vault_path = self.paths.vault_path(vault_id);
        vfs::write(vault_path, buffer.as_ref()).await?;
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache().get(summary.id()).is_none() {
                self.create_cache_entry(summary, None).await?;
            }
        }
        Ok(())
    }

    /// Close the current open vault.
    pub(crate) fn close_vault(&mut self) {
        self.state.close_vault();
    }

    /// Get a reference to the commit tree for an event log file.
    pub fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache
            .get(summary.id())
            .map(|event_log| event_log.tree())
    }

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current().map(|c| c.id().clone());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_vault();
            }
        }

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        // Remove from the state of managed vaults
        self.state.remove_summary(summary);

        Ok(())
    }

    /// Create a new account or vault.
    pub(crate) async fn prepare_folder(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
        is_account: bool,
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        let key = if let Some(key) = key {
            key
        } else {
            let (passphrase, _) = generate_passphrase()?;
            AccessKey::Password(passphrase)
        };

        let mut builder = VaultBuilder::new();
        if let Some(name) = name {
            builder = builder.public_name(name);
        }
        if is_account {
            builder = builder.flags(VaultFlags::DEFAULT);
        }
        let vault = match &key {
            AccessKey::Password(password) => {
                builder.password(password.clone(), None).await?
            }
            AccessKey::Identity(id) => {
                builder.shared(id, vec![], true).await?
            }
        };

        let buffer = encode(&vault).await?;

        let summary = vault.summary().clone();

        if self.state.mirror() {
            self.write_vault_file(summary.id(), &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault)).await?;

        Ok((buffer, key, summary))
    }

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    pub async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: Option<&AccessKey>,
    ) -> Result<(Event, Summary)> {
        let (exists, write_event, summary) =
            self.upsert_vault_buffer(buffer.as_ref(), key).await?;

        // If there is an existing folder
        // and we are overwriting then log the update
        // folder event
        let account_event = if exists {
            AccountEvent::UpdateFolder(
                *summary.id(),
                buffer.as_ref().to_owned(),
            )
        // Otherwise a create event
        } else {
            AccountEvent::CreateFolder(
                *summary.id(),
                buffer.as_ref().to_owned(),
            )
        };

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        let audit_event: AuditEvent = (self.address(), &account_event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        let event = Event::Folder(account_event, write_event);
        Ok((event, summary))
    }

    /// Remove a vault file and event log file.
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.paths.vault_path(summary.id());
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Remove the local event log file
        let event_log_path = self.paths.event_log_path(summary.id());
        if vfs::try_exists(&event_log_path).await? {
            vfs::remove_file(&event_log_path).await?;
        }
        Ok(())
    }

    /// Create a new folder.
    pub async fn create_folder(
        &mut self,
        name: String,
        key: Option<AccessKey>,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        let (buf, key, summary) =
            self.prepare_folder(Some(name), key, false).await?;

        let account_event =
            AccountEvent::CreateFolder(*summary.id(), buf.clone());
        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        let audit_event: AuditEvent = (self.address(), &account_event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok((buf, key, summary, account_event))
    }

    /// Create or update a vault.
    async fn upsert_vault_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: Option<&AccessKey>,
    ) -> Result<(bool, WriteEvent, Summary)> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let exists = self.find(|s| s.id() == vault.id()).is_some();
        let summary = vault.summary().clone();

        #[cfg(feature = "search")]
        if exists {
            if let Some(index) = self.index.as_mut() {
                // Clean entries from the search index
                index.remove_folder(summary.id()).await;
            }
        }

        // Always write out the updated buffer
        if self.state.mirror() {
            self.write_vault_file(summary.id(), &buffer).await?;
        }

        if !exists {
            // Add the summary to the vaults we are managing
            self.state.add_summary(summary.clone());
        } else {
            // Otherwise update with the new summary
            if let Some(position) = self
                .state
                .summaries()
                .iter()
                .position(|s| s.id() == summary.id())
            {
                let existing =
                    self.state.summaries_mut().get_mut(position).unwrap();
                *existing = summary.clone();
            }
        }

        #[cfg(feature = "search")]
        if let Some(key) = key {
            if let Some(index) = self.index.as_mut() {
                // Ensure the imported secrets are in the search index
                index.add_vault(vault.clone(), key).await?;
            }
        }

        // Initialize the local cache for event log
        self.create_cache_entry(&summary, Some(vault)).await?;

        Ok((
            exists,
            WriteEvent::CreateVault(buffer.as_ref().to_owned()),
            summary,
        ))
    }

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent>,
    ) -> Result<Vec<u8>> {
        let buffer = if self.state.mirror() {
            // Write the vault to disc
            let buffer = encode(vault).await?;
            self.write_vault_file(summary.id(), &buffer).await?;
            buffer
        } else {
            encode(vault).await?
        };

        // Apply events to the event log
        let event_log = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        event_log.clear().await?;
        event_log.apply(events.iter().collect()).await?;

        Ok(buffer)
    }

    /// Compact an event log file.
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_event_log, old_size, new_size) =
            event_log_file.compact().await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        *event_log_file = compact_event_log;

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(summary, None).await?;

        let account_event =
            AccountEvent::CompactFolder(*summary.id(), buffer);

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok((old_size, new_size))
    }

    /// Load a vault by reducing it from the event log stored on disc.
    async fn reduce_event_log(
        &mut self,
        summary: &Summary,
    ) -> Result<Vault> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        Ok(EventReducer::new()
            .reduce(event_log_file)
            .await?
            .build(true)
            .await?)
    }

    /// Load folders from the local disc.
    ///
    /// Creates the in-memory event logs for each folder on disc.
    pub async fn load_folders(&mut self) -> Result<&[Summary]> {
        let storage = self.paths.vaults_dir();
        let mut summaries = Vec::new();
        let mut contents = vfs::read_dir(&storage).await?;
        while let Some(entry) = contents.next_entry().await? {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(path).await?;
                    if summary.flags().is_system() {
                        continue;
                    }
                    summaries.push(summary);
                }
            }
        }

        self.load_caches(&summaries).await?;
        self.state.set_summaries(summaries);
        Ok(self.list_folders())
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<Vec<Event>> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;

        let mut events = Vec::new();

        #[cfg(feature = "files")]
        {
            let mut file_events = self.delete_folder_files(&summary).await?;
            self.file_log.apply(file_events.iter().collect()).await?;
            for event in file_events.drain(..) {
                events.push(Event::File(event));
            }
        }

        // Clean the search index
        #[cfg(feature = "search")]
        if let Some(index) = self.index.as_mut() {
            index.remove_folder(summary.id()).await;
        }

        let account_event = AccountEvent::DeleteFolder(*summary.id());
        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        let audit_event: AuditEvent = (self.address(), &account_event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        events.insert(0, Event::Account(account_event));

        Ok(events)
    }

    /// Set the name of a vault.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<Event> {
        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.as_ref().to_owned());
            }
        }

        // Now update the in-memory name for the current selected vault
        if let Some(keeper) = self.current_mut() {
            if keeper.vault().id() == summary.id() {
                keeper.set_vault_name(name.as_ref().to_owned()).await?;
            }
        }

        // Update the vault on disc
        let vault_path = self.paths.vault_path(summary.id());
        let vault_file = VaultWriter::open(&vault_path).await?;
        let mut access = VaultWriter::new(vault_path, vault_file)?;
        access.set_vault_name(name.as_ref().to_owned()).await?;

        let event = WriteEvent::SetVaultName(name.as_ref().to_owned());
        self.patch(summary, vec![&event]).await?;

        let account_event = AccountEvent::RenameFolder(
            *summary.id(),
            name.as_ref().to_owned(),
        );

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        let audit_event: AuditEvent = (self.address(), &account_event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(Event::Account(account_event))
    }

    /// Get the description of the currently open vault.
    pub async fn description(&self) -> Result<String> {
        let keeper = self.current().ok_or(Error::NoOpenVault)?;
        let meta = keeper.vault_meta().await?;
        Ok(meta.description().to_owned())
    }

    /// Set the description of the currently open vault.
    pub async fn set_description(
        &mut self,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let mut meta = keeper.vault_meta().await?;
        meta.set_description(description.as_ref().to_owned());
        let event = keeper.set_vault_meta(&meta).await?;
        self.patch(&summary, vec![&event]).await?;
        Ok(event)
    }

    /// Apply events to an existing folder.
    ///
    /// If the storage is mirroring changes to vault files
    /// the events are written to the vault file before
    /// applying to the folder event log.
    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<&WriteEvent>,
    ) -> Result<()> {
        // Apply events to the vault file on disc
        if self.state.mirror && !self.state.head_only {
            let vault_path = self.paths.vault_path(summary.id());
            let vault_file = VaultWriter::open(&vault_path).await?;
            let mut mirror = VaultWriter::new(vault_path, vault_file)?;
            for event in events.clone() {
                match event {
                    WriteEvent::CreateSecret(secret_id, vault_commit) => {
                        let hash = vault_commit.0.clone();
                        let entry = vault_commit.1.clone();
                        mirror.insert(*secret_id, hash, entry).await?;
                    }
                    WriteEvent::UpdateSecret(secret_id, vault_commit) => {
                        let hash = vault_commit.0.clone();
                        let entry = vault_commit.1.clone();
                        mirror.update(secret_id, hash, entry).await?;
                    }
                    WriteEvent::SetVaultName(name) => {
                        mirror.set_vault_name(name.to_owned()).await?;
                    }
                    WriteEvent::SetVaultMeta(meta) => {
                        mirror.set_vault_meta(meta.clone()).await?;
                    }
                    WriteEvent::DeleteSecret(secret_id) => {
                        mirror.delete(secret_id).await?;
                    }
                    _ => {} // Ignore CreateVault and Noop
                }
            }
        }

        // Apply events to the event log file
        let event_log = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        event_log.apply(events).await?;

        Ok(())
    }

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    pub(crate) async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        let (new_key, new_vault, event_log_events) =
            ChangePassword::new(vault, current_key, new_key, None)
                .build()
                .await?;

        let buffer = self
            .update_vault(vault.summary(), &new_vault, event_log_events)
            .await?;

        let account_event =
            AccountEvent::ChangeFolderPassword(*vault.id(), buffer);

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_key)).await?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(&new_key).await?;
            }
        }

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(new_key)
    }

    /// Verify an event log.
    pub async fn verify(&self, summary: &Summary) -> Result<()> {
        use crate::commit::event_log_commit_tree_file;
        let event_log_path = self.paths.event_log_path(summary.id());
        event_log_commit_tree_file(&event_log_path, true, |_| {}).await?;
        Ok(())
    }

    /// Get the history of events for a vault.
    pub async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, Timestamp, WriteEvent)>> {
        let event_log = self
            .cache()
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let mut records = Vec::new();
        let mut it = event_log.iter().await?;
        while let Some(record) = it.next_entry().await? {
            let event = event_log.decode_event(&record).await?;
            let commit = CommitHash(record.commit());
            let time = record.time().clone();
            records.push((commit, time, event));
        }
        Ok(records)
    }

    /// Commit state of the identity folder.
    pub async fn identity_state(&self) -> Result<CommitState> {
        let reader = self.identity_log.read().await;
        reader.tree().commit_state()
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    pub async fn commit_state(
        &self,
        summary: &Summary,
    ) -> Result<CommitState> {
        let log_file = self
            .cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        log_file.tree().commit_state()
    }
}

#[cfg(feature = "account")]
impl Storage {
    /// Create a secret in the currently open vault.
    pub(crate) async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        mut options: AccessOptions,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        let index_doc = if let Some(index) = &self.index {
            let search = index.search();
            let index = search.read().await;
            Some(index.prepare(
                summary.id(),
                secret_data.id(),
                secret_data.meta(),
                secret_data.secret(),
            ))
        } else {
            None
        };

        let event = {
            let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper.create(&secret_data).await?
        };

        #[cfg(feature = "files")]
        {
            let events = self
                .create_files(
                    &summary,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;
            self.append_file_mutation_events(&events).await?;
        }

        self.patch(&summary, vec![&event]).await?;

        if let (Some(index), Some(index_doc)) = (&self.index, index_doc) {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(event)
    }

    /// Read a secret in the currently open folder.
    pub(crate) async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let result =
            keeper.read(id).await?.ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open folder.
    pub(crate) async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        mut options: AccessOptions,
    ) -> Result<WriteEvent> {
        let (old_meta, old_secret, _) = self.read_secret(secret_id).await?;
        let old_secret_data =
            SecretRow::new(*secret_id, old_meta, old_secret);

        let secret_data = if let Some(secret) = secret {
            SecretRow::new(*secret_id, meta, secret)
        } else {
            let mut secret_data = old_secret_data.clone();
            secret_data.meta = meta;
            secret_data
        };

        let event = self.write_secret(secret_id, secret_data.clone()).await?;

        // Must update the files before moving so checksums are correct
        #[cfg(feature = "files")]
        {
            let folder = {
                let keeper = self.current().ok_or(Error::NoOpenVault)?;
                keeper.summary().clone()
            };
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

        Ok(event)
    }

    /// Write a secret in the current open folder.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    pub(crate) async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        secret_data.meta.touch();

        let index_doc = if let Some(index) = &self.index {
            let search = index.search();
            let mut index = search.write().await;
            // Must remove from the index before we
            // prepare a new document otherwise the
            // document would be stale as `prepare()`
            // and `commit()` are for new documents
            index.remove(summary.id(), id);

            Some(index.prepare(
                summary.id(),
                id,
                secret_data.meta(),
                secret_data.secret(),
            ))
        } else {
            None
        };

        let event = {
            let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper
                .update(id, secret_data.meta, secret_data.secret)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };
        self.patch(&summary, vec![&event]).await?;

        if let (Some(index), Some(index_doc)) = (&self.index, index_doc) {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    pub(crate) async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        mut options: AccessOptions,
    ) -> Result<WriteEvent> {
        let (meta, secret, _) = self.read_secret(secret_id).await?;
        let secret_data = SecretRow::new(*secret_id, meta, secret);

        let event = self.remove_secret(secret_id).await?;

        #[cfg(feature = "files")]
        {
            let folder = {
                let keeper = self.current().ok_or(Error::NoOpenVault)?;
                keeper.summary().clone()
            };

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

        Ok(event)
    }

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    pub(crate) async fn remove_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        let event = {
            let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper.delete(id).await?.ok_or(Error::SecretNotFound(*id))?
        };
        self.patch(&summary, vec![&event]).await?;

        if let Some(index) = &self.index {
            let search = index.search();
            let mut writer = search.write().await;
            writer.remove(summary.id(), id);
        }

        Ok(event)
    }
}

/// Collection of in-memory vaults.
pub(super) struct LocalState {
    /// Whether this state should mirror changes to disc.
    mirror: bool,
    /// Vault files should only contain header information.
    ///
    /// Useful for server implementations.
    head_only: bool,
    /// Vaults managed by this state.
    summaries: Vec<Summary>,
    /// Currently selected in-memory vault.
    current: Option<Gatekeeper>,
}

impl LocalState {
    /// Create a new node state.
    pub fn new(mirror: bool, head_only: bool) -> Self {
        Self {
            mirror,
            head_only,
            summaries: Default::default(),
            current: None,
        }
    }

    /// Determine if mirroring is enabled.
    fn mirror(&self) -> bool {
        self.mirror
    }

    /// Current in-memory vault.
    fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Mutable reference to the current in-memory vault.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Vault summaries.
    pub fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Mutable reference to the vault summaries.
    fn summaries_mut(&mut self) -> &mut [Summary] {
        self.summaries.as_mut_slice()
    }

    /// Set the summaries for this state.
    fn set_summaries(&mut self, summaries: Vec<Summary>) {
        self.summaries = summaries;
        self.summaries.sort();
    }

    /// Add a summary to this state.
    pub fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
    }

    /// Remove a summary from this state.
    fn remove_summary(&mut self, summary: &Summary) {
        if let Some(position) =
            self.summaries.iter().position(|s| s.id() == summary.id())
        {
            self.summaries.remove(position);
            self.summaries.sort();
        }
    }

    /// Find a summary in this state by reference.
    fn find_vault(&self, vault: &FolderRef) -> Option<&Summary> {
        match vault {
            FolderRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            FolderRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Find a summary in this state.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    /// Set the current folder and unlock it.
    async fn open_vault(
        &mut self,
        key: &AccessKey,
        vault: Vault,
        vault_path: PathBuf,
    ) -> Result<()> {
        let mut keeper = if self.mirror {
            let vault_file = VaultWriter::open(&vault_path).await?;
            let mirror = VaultWriter::new(vault_path, vault_file)?;
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };

        keeper
            .unlock(key)
            .await
            .map_err(|_| Error::VaultUnlockFail)?;
        self.current = Some(keeper);
        Ok(())
    }

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }
}
