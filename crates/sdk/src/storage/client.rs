//! Storage backed by the filesystem.
use crate::{
    commit::{CommitHash, CommitState},
    constants::VAULT_EXT,
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, Event, EventLogExt, EventRecord,
        FolderEventLog, FolderPatch, FolderReducer, IntoRecord, ReadEvent,
        WriteEvent,
    },
    identity::FolderKeys,
    passwd::diceware::generate_passphrase,
    prelude::{VaultFlags, EVENT_LOG_EXT},
    signer::ecdsa::Address,
    storage::{AccessOptions, AccountPack, DiscFolder, NewFolderOptions},
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        BuilderCredentials, ChangePassword, FolderRef, Header, Summary,
        Vault, VaultBuilder, VaultCommit, VaultId,
    },
    vfs, Error, Paths, Result, UtcDateTime,
};

use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use std::{borrow::Cow, collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use crate::account::archive::RestoreTargets;

#[cfg(feature = "audit")]
use crate::audit::AuditEvent;

use crate::{
    device::{DevicePublicKey, TrustedDevice},
    events::{DeviceEvent, DeviceEventLog, DeviceReducer},
};

#[cfg(feature = "files")]
use crate::events::{FileEvent, FileEventLog};

#[cfg(feature = "files")]
use crate::storage::files::FileMutationEvent;

#[cfg(feature = "search")]
use crate::storage::search::{AccountSearch, DocumentCount};

/// Storage change event with an optional
/// collection of file mutation events.
#[doc(hidden)]
pub struct StorageChangeEvent {
    /// Write event.
    pub event: WriteEvent,
    /// Collection of file mutation events.
    #[cfg(feature = "files")]
    pub file_events: Vec<FileMutationEvent>,
}

/// Client storage for folders loaded into memory and mirrored to disc.
pub struct ClientStorage {
    /// Address of the account owner.
    pub(super) address: Address,

    /// Folders managed by this storage.
    pub(super) summaries: Vec<Summary>,

    /// Currently selected folder.
    pub(super) current: Option<Summary>,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

    /// Search index.
    #[cfg(feature = "search")]
    pub index: Option<AccountSearch>,

    /// Identity folder event log.
    ///
    /// This is a clone of the main identity folder
    /// event log and is defined here so we can
    /// get the commit state for synchronization.
    pub identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub account_log: Arc<RwLock<AccountEventLog>>,

    /// Folder event logs.
    pub cache: HashMap<VaultId, DiscFolder>,

    /// Device event log.
    pub device_log: Arc<RwLock<DeviceEventLog>>,

    /// Reduced collection of devices.
    pub devices: IndexSet<TrustedDevice>,

    /// File event log.
    #[cfg(feature = "files")]
    pub file_log: Arc<RwLock<FileEventLog>>,

    /// Password for file encryption.
    #[cfg(feature = "files")]
    pub(super) file_password: Option<secrecy::SecretString>,
}

impl ClientStorage {
    /// Create unauthenticated folder storage for client-side access.
    pub async fn new_unauthenticated(
        address: Address,
        paths: Arc<Paths>,
    ) -> Result<Self> {
        paths.ensure().await?;

        let identity_log = Arc::new(RwLock::new(
            FolderEventLog::new(paths.identity_events()).await?,
        ));

        let account_log = Arc::new(RwLock::new(
            AccountEventLog::new_account(paths.account_events()).await?,
        ));

        let device_log = Arc::new(RwLock::new(
            DeviceEventLog::new_device(paths.device_events()).await?,
        ));

        #[cfg(feature = "files")]
        let file_log = Arc::new(RwLock::new(
            FileEventLog::new_file(paths.file_events()).await?,
        ));

        let mut storage = Self {
            address,
            summaries: Vec::new(),
            current: None,
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            #[cfg(feature = "search")]
            index: None,
            device_log,
            devices: Default::default(),
            #[cfg(feature = "files")]
            file_log,
            #[cfg(feature = "files")]
            file_password: None,
        };

        storage.load_folders().await?;

        Ok(storage)
    }

    /// Create folder storage for client-side access.
    pub async fn new_authenticated(
        address: Address,
        data_dir: Option<PathBuf>,
        identity_log: Arc<RwLock<FolderEventLog>>,
        device: TrustedDevice,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir().map_err(|_| Error::NoCache)?
        };

        let dirs = Paths::new(data_dir, address.to_string());
        Self::new_paths(Arc::new(dirs), address, identity_log, device).await
    }

    /// Create new storage backed by files on disc.
    async fn new_paths(
        paths: Arc<Paths>,
        address: Address,
        identity_log: Arc<RwLock<FolderEventLog>>,
        device: TrustedDevice,
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

        let (device_log, devices) =
            Self::initialize_device_log(&paths, device).await?;

        #[cfg(feature = "files")]
        let file_log = Self::initialize_file_log(&paths).await?;

        Ok(Self {
            address,
            summaries: Vec::new(),
            current: None,
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            #[cfg(feature = "search")]
            index: Some(AccountSearch::new()),
            device_log: Arc::new(RwLock::new(device_log)),
            devices,
            #[cfg(feature = "files")]
            file_log: Arc::new(RwLock::new(file_log)),
            #[cfg(feature = "files")]
            file_password: None,
        })
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }

    async fn initialize_device_log(
        paths: &Paths,
        device: TrustedDevice,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let log_file = paths.device_events();

        let mut event_log = DeviceEventLog::new_device(log_file).await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        tracing::debug!(needs_init = %needs_init, "device_log");

        // Trust this device on initialization if the event
        // log is empty so that we are backwards compatible with
        // accounts that existed before device event logs.
        if needs_init {
            tracing::debug!(
              public_key = %device.public_key(), "initialize_root_device");
            let event = DeviceEvent::Trust(device);
            event_log.apply(vec![&event]).await?;
        }

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    /// Collection of trusted devices.
    pub fn devices(&self) -> &IndexSet<TrustedDevice> {
        &self.devices
    }

    /// Set the password for file encryption.
    #[cfg(feature = "files")]
    pub fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    ) {
        self.file_password = file_password;
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(paths: &Paths) -> Result<FileEventLog> {
        let log_file = paths.file_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = FileEventLog::new_file(log_file).await?;
        event_log.load_tree().await?;

        tracing::debug!(needs_init = %needs_init, "file_log");

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

    /// Cache of in-memory event logs.
    pub fn cache(&self) -> &HashMap<VaultId, DiscFolder> {
        &self.cache
    }

    /// Mutable in-memory event logs.
    pub fn cache_mut(&mut self) -> &mut HashMap<VaultId, DiscFolder> {
        &mut self.cache
    }

    /// Find a summary in this storage.
    pub fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        match vault {
            FolderRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            FolderRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Find a summary in this storage.
    pub fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    /// Computed storage paths.
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
                if let Some(folder) = self.cache.get_mut(summary.id()) {
                    let keeper = folder.keeper_mut();
                    keeper.unlock(key).await?;
                    writer.add_folder(keeper).await?;
                }
            }
        }

        let count = if let Some(index) = &self.index {
            index.document_count().await
        } else {
            Default::default()
        };

        Ok(count)
    }

    /// Mark a folder as the currently open folder.
    pub(crate) async fn open_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<ReadEvent> {
        self.find(|s| s.id() == summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        self.current = Some(summary.clone());
        Ok(ReadEvent::ReadVault)
    }

    /// Close the current open folder.
    pub(crate) fn close_folder(&mut self) {
        self.current = None;
    }

    /// Create the data for a new account.
    pub async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        let create_account = Event::CreateAccount(account.address);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.address(), &create_account).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        // Import folders
        for folder in &account.folders {
            let buffer = encode(folder).await?;
            let (event, _) =
                self.import_folder(buffer, None, true, None).await?;
            events.push(event);
        }

        events.insert(0, create_account);

        Ok(events)
    }

    /// Create folders from a collection of folder patches.
    ///
    /// If the folders already exist they will be overwritten.
    pub async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()> {
        for (folder_id, patch) in patches {
            let records: Vec<EventRecord> = patch.into();
            let (folder, vault) =
                self.initialize_folder(&folder_id, records).await?;

            {
                let event_log = folder.event_log();
                let event_log = event_log.read().await;
                tracing::info!(
                  folder_id = %folder_id,
                  root = ?event_log.tree().root().map(|c| c.to_string()),
                  "import_folder_patch");
            }

            self.cache.insert(folder_id, folder);
            let summary = vault.summary().to_owned();
            self.add_summary(summary.clone());
        }
        Ok(())
    }

    /// Initialize a folder from an event log.
    ///
    /// If an event log exists for the folder identifer
    /// it is replaced with the new event records.
    async fn initialize_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<(DiscFolder, Vault)> {
        let vault_path = self.paths.vault_path(folder_id);

        // Prepare the vault file on disc
        let vault = {
            // We need a vault on disc to create the event log
            // so set a placeholder
            let vault: Vault = Default::default();
            let buffer = encode(&vault).await?;
            self.write_vault_file(folder_id, buffer).await?;

            let folder = DiscFolder::new(&vault_path).await?;
            let event_log = folder.event_log();
            let mut event_log = event_log.write().await;
            event_log.clear().await?;
            event_log.apply_records(records).await?;

            let vault = FolderReducer::new()
                .reduce(&*event_log)
                .await?
                .build(true)
                .await?;

            let buffer = encode(&vault).await?;
            self.write_vault_file(folder_id, buffer).await?;

            vault
        };

        // Setup the folder access to the latest vault information
        // and load the merkle tree
        let folder = DiscFolder::new(&vault_path).await?;
        let event_log = folder.event_log();
        let mut event_log = event_log.write().await;
        event_log.load_tree().await?;

        Ok((folder, vault))
    }

    /// Restore a folder from an event log.
    pub async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        let (mut folder, vault) =
            self.initialize_folder(folder_id, records).await?;

        // Unlock the folder
        folder.unlock(key).await?;
        self.cache.insert(*folder_id, folder);

        let summary = vault.summary().to_owned();
        self.add_summary(summary.clone());

        #[cfg(feature = "search")]
        if let Some(index) = self.index.as_mut() {
            // Ensure the imported secrets are in the search index
            index.add_vault(vault, key).await?;
        }

        Ok(summary)
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    #[cfg(feature = "archive")]
    pub async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()> {
        let RestoreTargets { vaults, .. } = targets;

        // We may be restoring vaults that do not exist
        // so we need to update the cache
        let summaries = vaults
            .iter()
            .map(|(_, v)| v.summary().clone())
            .collect::<Vec<_>>();
        self.load_caches(&summaries).await?;

        for (_, vault) in vaults {
            // Prepare a fresh log of event log events
            let (vault, events) = FolderReducer::split(vault.clone()).await?;

            self.update_vault(vault.summary(), &vault, events).await?;

            // Refresh the in-memory and disc-based mirror
            let key = folder_keys
                .find(vault.id())
                .ok_or(Error::NoFolderPassword(*vault.id()))?;
            self.refresh_vault(vault.summary(), key).await?;
        }

        Ok(())
    }

    /// List the folder summaries for this storage.
    pub fn list_folders(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Reference to the currently open folder.
    pub fn current_folder(&self) -> Option<Summary> {
        self.current.clone()
    }

    /// Create new event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<()> {
        let vault_path = self.paths.vault_path(summary.id());
        let mut event_log = DiscFolder::new(&vault_path).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.clear().await?;

            let (_, events) = FolderReducer::split(vault).await?;

            let mut records = Vec::with_capacity(events.len());
            for event in events.iter() {
                records.push(event.default_record().await?);
            }
            if let (Some(creation_time), Some(event)) =
                (creation_time, records.get_mut(0))
            {
                event.set_time(creation_time.to_owned());
            }
            event_log.apply_records(records).await?;
        }

        self.cache.insert(*summary.id(), event_log);

        Ok(())
    }

    /// Create the event log on disc for a pending folder.
    async fn create_pending_event_log(
        &self,
        summary: &Summary,
        vault: Vault,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<()> {
        let vault_path = self.paths.pending_vault_path(summary.id());
        let mut event_log = DiscFolder::new(&vault_path).await?;

        // Must truncate the event log so that importing vaults
        // does not end up with multiple create vault events
        event_log.clear().await?;

        let (_, events) = FolderReducer::split(vault).await?;

        let mut records = Vec::with_capacity(events.len());
        for event in events.iter() {
            records.push(event.default_record().await?);
        }

        if let (Some(creation_time), Some(event)) =
            (creation_time, records.get_mut(0))
        {
            event.set_time(creation_time.to_owned());
        }
        event_log.apply_records(records).await?;

        Ok(())
    }

    /// Promote a pending folder.
    ///
    /// A pending folder is one that was created with the `LOCAL`
    /// and `NO_SYNC` flags set.
    ///
    /// The `LOCAL` flag indicates the folder is local-first and
    /// other devices when they see the `LOCAL` flag set when an
    /// [AccountEvent::CreateFolder] event is merged must create
    /// stub files in the pending folder.
    ///
    /// Later, if a device decides to remove the `NO_SYNC` flag
    /// then the server will include the folder in diff contents.
    ///
    /// Clients should then try to merge the diff contents but the
    /// folder may not exist so they can
    /// call `try_promote_pending_folder` first.
    ///
    /// Returns a boolean indicating whether a folder was promoted
    /// or not.
    #[doc(hidden)]
    pub async fn try_promote_pending_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<bool> {
        let pending_vault = self.paths.pending_vault_path(folder_id);
        let mut pending_event = pending_vault.clone();
        pending_event.set_extension(EVENT_LOG_EXT);

        let vault = self.paths.vault_path(folder_id);
        let event = self.paths.event_log_path(folder_id);

        let has_pending_folder = vfs::try_exists(&pending_vault).await?
            && vfs::try_exists(&pending_event).await?;

        if has_pending_folder {
            // Move the files into place
            vfs::rename(&pending_vault, &vault).await?;
            vfs::rename(&pending_event, &event).await?;

            let summary = Header::read_summary_file(&vault).await?;
            let folder = DiscFolder::new(&vault).await?;
            let event_log = folder.event_log();
            let mut event_log = event_log.write().await;
            event_log.load_tree().await?;
            self.cache.insert(*summary.id(), folder);
            self.add_summary(summary);
            Ok(true)
        } else {
            Ok(false)
        }
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
        key: &AccessKey,
    ) -> Result<Vec<u8>> {
        let vault = self.reduce_event_log(summary).await?;

        // Rewrite the on-disc version
        let buffer = encode(&vault).await?;
        self.write_vault_file(summary.id(), &buffer).await?;

        if let Some(folder) = self.cache.get_mut(summary.id()) {
            let keeper = folder.keeper_mut();
            keeper.lock();
            keeper.replace_vault(vault.clone(), false).await?;
            keeper.unlock(key).await?;
        }

        Ok(buffer)
    }

    /// Read a vault from the file on disc.
    pub(crate) async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        let buffer = self.read_vault_file(id).await?;
        decode(&buffer).await
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
        vfs::write_exclusive(vault_path, buffer.as_ref()).await?;
        Ok(())
    }

    /// Write the buffer for a local vault placeholder to disc.
    async fn write_pending_vault_file(
        &self,
        vault_id: &VaultId,
        buffer: impl AsRef<[u8]>,
    ) -> Result<()> {
        let vault_path = self.paths.pending_vault_path(vault_id);
        vfs::write_exclusive(vault_path, buffer.as_ref()).await?;
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache().get(summary.id()).is_none() {
                self.create_cache_entry(summary, None, None).await?;
            }
        }
        Ok(())
    }

    /// Unlock all folders.
    pub async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        for (id, folder) in self.cache.iter_mut() {
            if let Some(key) = keys.find(id) {
                folder.unlock(key).await?;
            } else {
                tracing::error!(
                    folder_id = %id,
                    "unlock::no_folder_key",
                );
            }
        }
        Ok(())
    }

    /// Lock all folders.
    pub async fn lock(&mut self) {
        for (_, folder) in self.cache.iter_mut() {
            folder.lock();
        }
    }

    /// Unlock a folder.
    pub async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        let folder = self
            .cache
            .get_mut(id)
            .ok_or(Error::CacheNotAvailable(*id))?;
        folder.unlock(key).await?;
        Ok(())
    }

    /// Lock a folder.
    pub async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        let folder = self
            .cache
            .get_mut(id)
            .ok_or(Error::CacheNotAvailable(*id))?;
        folder.lock();
        Ok(())
    }

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current_folder().map(|c| *c.id());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_folder();
            }
        }

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        // Remove from the state of managed vaults
        self.remove_summary(summary);

        Ok(())
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

    /// Prepare a new folder.
    async fn prepare_folder(
        &mut self,
        name: Option<String>,
        mut options: NewFolderOptions,
        /*
        key: Option<AccessKey>,
        cipher: Option<Cipher>,
        kdf: Option<KeyDerivation>,
        */
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        let key = if let Some(key) = options.key.take() {
            key
        } else {
            let (passphrase, _) = generate_passphrase()?;
            AccessKey::Password(passphrase)
        };

        let mut builder = VaultBuilder::new()
            .flags(options.flags)
            .cipher(options.cipher.unwrap_or_default())
            .kdf(options.kdf.unwrap_or_default());
        if let Some(name) = name {
            builder = builder.public_name(name);
        }

        let vault = match &key {
            AccessKey::Password(password) => {
                builder
                    .build(BuilderCredentials::Password(
                        password.clone(),
                        None,
                    ))
                    .await?
            }
            AccessKey::Identity(id) => {
                builder
                    .build(BuilderCredentials::Shared {
                        owner: id,
                        recipients: vec![],
                        read_only: true,
                    })
                    .await?
            }
        };

        let buffer = encode(&vault).await?;

        let summary = vault.summary().clone();

        self.write_vault_file(summary.id(), &buffer).await?;

        // Add the summary to the vaults we are managing
        self.add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault), None).await?;

        self.unlock_folder(summary.id(), &key).await?;

        Ok((buffer, key, summary))
    }

    /// Add a summary to this state.
    fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
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
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)> {
        let (exists, write_event, summary) = self
            .upsert_vault_buffer(buffer.as_ref(), key, creation_time)
            .await?;

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

        if apply_event {
            let mut account_log = self.account_log.write().await;
            account_log.apply(vec![&account_event]).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

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
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        let (buf, key, summary) =
            self.prepare_folder(Some(name), options).await?;

        let account_event =
            AccountEvent::CreateFolder(*summary.id(), buf.clone());
        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok((buf, key, summary, account_event))
    }

    /// Create or update a vault.
    async fn upsert_vault_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: Option<&AccessKey>,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(bool, WriteEvent, Summary)> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let exists = self.find(|s| s.id() == vault.id()).is_some();
        let summary = vault.summary().clone();

        let is_local_folder =
            summary.flags.is_local() && summary.flags().is_sync_disabled();

        #[cfg(feature = "search")]
        if exists {
            if let Some(index) = self.index.as_mut() {
                // Clean entries from the search index
                index.remove_folder(summary.id()).await;
            }
        }

        // Always write out the updated buffer
        if is_local_folder {
            self.write_pending_vault_file(summary.id(), &buffer).await?;
        } else {
            self.write_vault_file(summary.id(), &buffer).await?;
        }

        if !is_local_folder {
            if !exists {
                // Add the summary to the vaults we are managing
                self.add_summary(summary.clone());
            } else {
                // Otherwise update with the new summary
                if let Some(position) =
                    self.summaries.iter().position(|s| s.id() == summary.id())
                {
                    let existing = self.summaries.get_mut(position).unwrap();
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
        }

        let event = vault.into_event().await?;

        if is_local_folder {
            self.create_pending_event_log(&summary, vault, creation_time)
                .await?;
        } else {
            // Initialize the local cache for event log
            self.create_cache_entry(&summary, Some(vault), creation_time)
                .await?;

            // Must ensure the folder is unlocked
            if let Some(key) = key {
                self.unlock_folder(summary.id(), key).await?;
            }
        }

        Ok((exists, event, summary))
    }

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent>,
    ) -> Result<Vec<u8>> {
        // Write the vault to disc
        let buffer = encode(vault).await?;
        self.write_vault_file(summary.id(), &buffer).await?;

        // Apply events to the event log
        let folder = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        folder.clear().await?;
        folder.apply(events.iter().collect()).await?;

        Ok(buffer)
    }

    /// Compact an event log file.
    pub async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<(AccountEvent, u64, u64)> {
        let (old_size, new_size) = {
            let folder = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let event_log = folder.event_log();
            let mut log_file = event_log.write().await;

            let (compact_event_log, old_size, new_size) =
                log_file.compact().await?;

            // Need to recreate the event log file and load the updated
            // commit tree
            *log_file = compact_event_log;

            (old_size, new_size)
        };

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(summary, key).await?;

        let account_event =
            AccountEvent::CompactFolder(*summary.id(), buffer);

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok((account_event, old_size, new_size))
    }

    /// Load a vault by reducing it from the event log stored on disc.
    async fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault> {
        let folder = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        FolderReducer::new()
            .reduce(&*log_file)
            .await?
            .build(true)
            .await
    }

    /// Read folders from the local disc.
    async fn read_folders(&self) -> Result<Vec<Summary>> {
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
        Ok(summaries)
    }

    /// Read folders from the local disc and create the in-memory
    /// event logs for each folder on disc.
    pub async fn load_folders(&mut self) -> Result<&[Summary]> {
        let summaries = self.read_folders().await?;
        self.load_caches(&summaries).await?;
        self.summaries = summaries;
        Ok(self.list_folders())
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;

        let mut events = Vec::new();

        #[cfg(feature = "files")]
        {
            let mut file_events =
                self.delete_folder_files(summary.id()).await?;
            let mut writer = self.file_log.write().await;
            writer.apply(file_events.iter().collect()).await?;
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

        if apply_event {
            let mut account_log = self.account_log.write().await;
            account_log.apply(vec![&account_event]).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        events.insert(0, Event::Account(account_event));

        Ok(events)
    }

    /// Remove a folder from the cache.
    pub async fn remove_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<bool> {
        let summary = self.find(|s| s.id() == folder_id).cloned();
        if let Some(summary) = summary {
            self.remove_local_cache(&summary)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Update the in-memory name for a folder.
    pub fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<()> {
        for item in self.summaries.iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.as_ref().to_owned());
                break;
            }
        }
        Ok(())
    }

    /// Update the in-memory name for a folder.
    pub fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()> {
        for item in self.summaries.iter_mut() {
            if item.id() == summary.id() {
                *item.flags_mut() = flags;
                break;
            }
        }
        Ok(())
    }

    /// Set the name of a vault.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_name(summary, name.as_ref())?;

        let folder = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        folder.rename_folder(name.as_ref()).await?;

        let account_event = AccountEvent::RenameFolder(
            *summary.id(),
            name.as_ref().to_owned(),
        );

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.address(), &account_event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(Event::Account(account_event))
    }

    /// Update the flags for a vault.
    pub async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_flags(summary, flags.clone())?;

        let folder = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let event = folder.update_folder_flags(flags).await?;
        let event = Event::Write(*summary.id(), event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(event)
    }

    /// Get the description of the currently open folder.
    pub async fn description(&self) -> Result<String> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.cache.get(summary.id()) {
            Ok(folder.description().await?)
        } else {
            Err(Error::CacheNotAvailable(*summary.id()))
        }
    }

    /// Set the description of the currently open folder.
    pub async fn set_description(
        &mut self,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.cache.get_mut(summary.id()) {
            Ok(folder.set_description(description).await?)
        } else {
            Err(Error::CacheNotAvailable(*summary.id()))
        }
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
        self.refresh_vault(vault.summary(), &new_key).await?;

        if let Some(folder) = self.cache.get_mut(vault.id()) {
            let keeper = folder.keeper_mut();
            keeper.unlock(&new_key).await?;
        }

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(new_key)
    }

    /// Verify an event log.
    pub async fn verify(&self, summary: &Summary) -> Result<()> {
        use crate::integrity::event_integrity;
        let path = self.paths.event_log_path(summary.id());
        let stream = event_integrity(&path);
        pin_mut!(stream);
        while let Some(event) = stream.next().await {
            event??;
        }
        Ok(())
    }

    /// Get the history of events for a vault.
    pub async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let folder = self
            .cache()
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let mut records = Vec::new();

        // TODO: prefer stream() here
        let mut it = log_file.iter(false).await?;
        while let Some(record) = it.next().await? {
            let event = log_file.decode_event(&record).await?;
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
        let folder = self
            .cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        log_file.tree().commit_state()
    }
}

#[cfg(feature = "account")]
impl ClientStorage {
    /// Create a secret in the currently open vault.
    pub(crate) async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        #[cfg(feature = "search")]
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
            let folder = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            folder.create_secret(&secret_data).await?
        };

        let result = StorageChangeEvent {
            event,
            #[cfg(feature = "files")]
            file_events: self
                .create_files(
                    &summary,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?,
        };

        #[cfg(feature = "files")]
        self.append_file_mutation_events(&result.file_events)
            .await?;

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) = (&self.index, index_doc) {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(result)
    }

    /// Read the encrypted contents of a secret.
    pub(crate) async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        let folder = self
            .cache
            .get(folder_id)
            .ok_or(Error::CacheNotAvailable(*folder_id))?;
        folder.raw_secret(secret_id).await
    }

    /// Read a secret in the currently open folder.
    pub(crate) async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        let folder = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let result = folder
            .read_secret(id)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open folder.
    pub(crate) async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
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

        let event = self
            .write_secret(secret_id, secret_data.clone(), true)
            .await?;

        let result = StorageChangeEvent {
            event,
            // Must update the files before moving so checksums are correct
            #[cfg(feature = "files")]
            file_events: {
                let folder =
                    self.current_folder().ok_or(Error::NoOpenVault)?;
                self.update_files(
                    &folder,
                    &folder,
                    &old_secret_data,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?
            },
        };

        #[cfg(feature = "files")]
        self.append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
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
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        secret_data.meta.touch();

        #[cfg(feature = "search")]
        let index_doc = if let Some(index) = &self.index {
            let search = index.search();
            let mut index = search.write().await;

            if is_update {
                // Must remove from the index before we
                // prepare a new document otherwise the
                // document would be stale as `prepare()`
                // and `commit()` are for new documents
                index.remove(summary.id(), id);
            }

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
            let folder = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            folder
                .update_secret(id, secret_data.meta, secret_data.secret)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };

        #[cfg(feature = "search")]
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
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        #[cfg(feature = "files")]
        let secret_data = {
            let (meta, secret, _) = self.read_secret(secret_id).await?;
            SecretRow::new(*secret_id, meta, secret)
        };

        let event = self.remove_secret(secret_id).await?;

        let result = StorageChangeEvent {
            event,
            // Must update the files before moving so checksums are correct
            #[cfg(feature = "files")]
            file_events: {
                let folder =
                    self.current_folder().ok_or(Error::NoOpenVault)?;
                self.delete_files(
                    &folder,
                    &secret_data,
                    None,
                    &mut options.file_progress,
                )
                .await?
            },
        };

        #[cfg(feature = "files")]
        self.append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    pub(crate) async fn remove_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        let event = {
            let folder = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            folder
                .delete_secret(id)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };

        #[cfg(feature = "search")]
        if let Some(index) = &self.index {
            let search = index.search();
            let mut writer = search.write().await;
            writer.remove(summary.id(), id);
        }

        Ok(event)
    }
}

impl ClientStorage {
    /// List trusted devices.
    pub fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        self.devices.iter().collect()
    }

    /// Patch the devices event log.
    pub async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        let mut event_log = self.device_log.write().await;
        event_log.apply(events.iter().collect()).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

        Ok(())
    }

    /// Revoke trust in a device.
    pub async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        let device =
            self.devices.iter().find(|d| d.public_key() == public_key);
        if device.is_some() {
            let event = DeviceEvent::Revoke(*public_key);

            let mut writer = self.device_log.write().await;
            writer.apply(vec![&event]).await?;

            let reducer = DeviceReducer::new(&*writer);
            self.devices = reducer.reduce().await?;
        }

        Ok(())
    }
}
