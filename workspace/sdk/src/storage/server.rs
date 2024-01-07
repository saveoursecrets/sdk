//! Server storage backed by the filesystem.
use crate::{
    commit::CommitState,
    constants::VAULT_EXT,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, EventLogExt, EventReducer,
        FolderEventLog,
    },
    signer::ecdsa::Address,
    vault::{Header, Summary, Vault, VaultAccess, VaultId, VaultWriter},
    vfs, Error, Paths, Result,
};

use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::{span, Level};

#[cfg(feature = "audit")]
use crate::audit::AuditEvent;

#[cfg(feature = "device")]
use crate::{
    device::{DevicePublicKey, TrustedDevice},
    events::{DeviceEventLog, DeviceReducer},
};

#[cfg(feature = "device")]
use std::collections::HashSet;

#[cfg(feature = "files")]
use crate::events::{FileEvent, FileEventLog};

/// Server folders loaded into memory and mirrored to disc.
pub struct ServerStorage {
    /// Address of the account owner.
    pub(super) address: Address,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

    /// Identity folder event log.
    pub(super) identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub(super) account_log: Arc<RwLock<AccountEventLog>>,

    /// Folder event logs.
    pub(super) cache: HashMap<VaultId, Arc<RwLock<FolderEventLog>>>,

    /// Device event log.
    #[cfg(feature = "device")]
    pub(super) device_log: Arc<RwLock<DeviceEventLog>>,

    /// Reduced collection of devices.
    #[cfg(feature = "device")]
    pub(super) devices: HashMap<DevicePublicKey, TrustedDevice>,

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
        Self::new_paths(Arc::new(dirs), address, identity_log).await
    }

    /// Create new storage backed by files on disc.
    async fn new_paths(
        paths: Arc<Paths>,
        address: Address,
        identity_log: Arc<RwLock<FolderEventLog>>,
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

        #[cfg(feature = "device")]
        let (device_log, devices) =
            Self::initialize_device_log(&*paths).await?;

        #[cfg(feature = "files")]
        let file_log = Self::initialize_file_log(&*paths).await?;

        Ok(Self {
            address,
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            #[cfg(feature = "device")]
            device_log: Arc::new(RwLock::new(device_log)),
            #[cfg(feature = "device")]
            devices,
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

    #[cfg(feature = "device")]
    async fn initialize_device_log(
        paths: &Paths,
    ) -> Result<(DeviceEventLog, HashMap<DevicePublicKey, TrustedDevice>)>
    {
        let span = span!(Level::DEBUG, "init_device_log");
        let _enter = span.enter();

        let log_file = paths.device_events();
        let mut event_log = DeviceEventLog::new_device(log_file).await?;
        event_log.load_tree().await?;

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
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
    pub fn cache(&self) -> &HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &self.cache
    }

    /// Get the mutable event log cache.
    pub fn cache_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &mut self.cache
    }

    /// Get the computed storage directories for the provider.
    pub fn paths(&self) -> Arc<Paths> {
        Arc::clone(&self.paths)
    }

    /// Create new event log cache entries.
    async fn create_cache_entry(&mut self, id: &VaultId) -> Result<()> {
        let event_log_path = self.paths.event_log_path(id);
        let mut event_log = FolderEventLog::new(&event_log_path).await?;
        event_log.load_tree().await?;
        self.cache.insert(*id, Arc::new(RwLock::new(event_log)));
        Ok(())
    }

    /// Remove a vault file and event log file.
    async fn remove_vault_file(&self, id: &VaultId) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.paths.vault_path(id);
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Remove the local event log file
        let event_log_path = self.paths.event_log_path(id);
        if vfs::try_exists(&event_log_path).await? {
            vfs::remove_file(&event_log_path).await?;
        }
        Ok(())
    }

    /// Load folders from the local disc.
    ///
    /// Creates the in-memory event logs for each folder on disc.
    pub async fn load_folders(&mut self) -> Result<Vec<Summary>> {
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

        // Create a cache entry for each summary if it does not
        // already exist.
        for summary in &summaries {
            // Ensure we don't overwrite existing data
            if self.cache.get(summary.id()).is_none() {
                self.create_cache_entry(summary.id()).await?;
            }
        }
        Ok(summaries)
    }

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    pub async fn import_folder(
        &mut self,
        id: &VaultId,
        buffer: impl AsRef<[u8]>,
    ) -> Result<()> {
        let exists = self.cache.get(id).is_some();

        let vault: Vault = decode(buffer.as_ref()).await?;
        let (vault, events) = EventReducer::split(vault).await?;

        if id != vault.id() {
            return Err(Error::VaultIdentifierMismatch(*id, *vault.id()));
        }

        let vault_path = self.paths.vault_path(id);
        let buffer = encode(&vault).await?;
        vfs::write(vault_path, &buffer).await?;

        self.create_cache_entry(id).await?;

        {
            let event_log = self.cache.get_mut(id).unwrap();
            let mut event_log = event_log.write().await;
            event_log.clear().await?;
            event_log.apply(events.iter().collect()).await?;
        }

        #[cfg(feature = "audit")]
        {
            // If there is an existing folder
            // and we are overwriting then log the update
            // folder event
            let account_event = if exists {
                AccountEvent::UpdateFolder(*id, buffer)
            // Otherwise a create event
            } else {
                AccountEvent::CreateFolder(*id, buffer)
            };

            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Delete a folder.
    pub async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        // Remove the files
        self.remove_vault_file(id).await?;

        // Remove local state
        self.cache.remove(id);

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

        #[cfg(feature = "audit")]
        {
            let account_event = AccountEvent::DeleteFolder(*id);
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Set the name of a vault.
    pub async fn rename_folder(
        &mut self,
        id: &VaultId,
        name: impl AsRef<str>,
    ) -> Result<()> {
        // Update the vault on disc
        let vault_path = self.paths.vault_path(id);
        let vault_file = VaultWriter::open(&vault_path).await?;
        let mut access = VaultWriter::new(vault_path, vault_file)?;
        access.set_vault_name(name.as_ref().to_owned()).await?;

        #[cfg(feature = "audit")]
        {
            let account_event =
                AccountEvent::RenameFolder(*id, name.as_ref().to_owned());
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

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
        let event_log = self
            .cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        let event_log = event_log.read().await;
        Ok(event_log.tree().commit_state()?)
    }
}

#[cfg(feature = "device")]
impl ServerStorage {
    /// List the public keys of trusted devices.
    pub fn list_device_keys(&self) -> HashSet<&DevicePublicKey> {
        self.devices.keys().collect()
    }
}
