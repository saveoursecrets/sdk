//! Storage backed by the filesystem.
use crate::{
    commit::{CommitHash, CommitState, CommitTree},
    constants::VAULT_EXT,
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, AuditEvent, Event, EventKind,
        EventLogExt, EventReducer, FolderEventLog, ReadEvent, WriteEvent,
    },
    identity::FolderKeys,
    passwd::{diceware::generate_passphrase, ChangePassword},
    signer::ecdsa::Address,
    storage::AccessOptions,
    storage::AccountPack,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        FolderRef, Gatekeeper, Header, Summary, Vault, VaultAccess,
        VaultBuilder, VaultCommit, VaultFlags, VaultId, VaultWriter,
    },
    vfs, Error, Paths, Result, Timestamp,
};

use secrecy::SecretString;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};

#[cfg(feature = "files")]
use crate::events::{FileEvent, FileEventLog};

/// Server folders loaded into memory and mirrored to disc.
pub struct ServerStorage {
    /// Address of the account owner.
    pub(super) address: Address,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

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
}

impl ServerStorage {

    /// Create folder storage for server-side access.
    pub async fn new(
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
    ) -> Result<Self> {
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
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            #[cfg(feature = "files")]
            file_log,
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

    /// Get the event log cache.
    pub fn cache(&self) -> &HashMap<VaultId, FolderEventLog> {
        &self.cache
    }

    /// Get the mutable event log cache.
    pub fn cache_mut(&mut self) -> &mut HashMap<VaultId, FolderEventLog> {
        &mut self.cache
    }

    /// Get the computed storage directories for the provider.
    pub fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
    }

    /// Create new event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()> {
        let event_log_path = self.paths.event_log_path(summary.id());
        let mut event_log = FolderEventLog::new(&event_log_path).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.clear().await?;

            let (vault, events) = EventReducer::split(vault).await?;
            event_log.apply(events.iter().collect()).await?;

            let buffer = encode(&vault).await?;
            self.write_vault_file(summary.id(), buffer).await?;
        }
        event_log.load_tree().await?;

        self.cache.insert(*summary.id(), event_log);

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

    /// Get a reference to the commit tree for an event log file.
    pub fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache
            .get(summary.id())
            .map(|event_log| event_log.tree())
    }

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        Ok(())
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

    /// Load a vault by reducing it from the event log stored on disc.
    async fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault> {
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
    pub async fn load_folders(&mut self) -> Result<()> {
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
        Ok(())
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
        
        /*
        #[cfg(feature = "files")]
        {
            let mut file_events = self.delete_folder_files(&summary).await?;
            self.file_log.apply(file_events.iter().collect()).await?;
            for event in file_events.drain(..) {
                events.push(Event::File(event));
            }
        }
        */

        let account_event = AccountEvent::DeleteFolder(*summary.id());
        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        let audit_event: AuditEvent = (self.address(), &account_event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        events.insert(0, Event::Account(account_event));

        Ok(events)
    }
    
    /*
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
    */

    /// Verify an event log.
    pub async fn verify(&self, summary: &Summary) -> Result<()> {
        use crate::commit::event_log_commit_tree_file;
        let event_log_path = self.paths.event_log_path(summary.id());
        event_log_commit_tree_file(&event_log_path, true, |_| {}).await?;
        Ok(())
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
