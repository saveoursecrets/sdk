//! Storage backed by the filesystem.
use crate::{
    files::ExternalFileManager, AccessOptions, AccountPack,
    ClientAccountStorage, ClientDeviceStorage, ClientFolderStorage,
    ClientSecretStorage, Error, NewFolderOptions, Result, StorageChangeEvent,
};
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use sos_backend::{
    reducers::FolderReducer, write_exclusive, Folder, StorageError,
};
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
use sos_core::{
    commit::{CommitHash, CommitState},
    SecretId, VaultId,
};
use sos_core::{
    constants::VAULT_EXT,
    crypto::AccessKey,
    decode, encode,
    events::{
        patch::FolderPatch, AccountEvent, Event, ReadEvent, WriteEvent,
    },
    AccountId, Paths, UtcDateTime,
};
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    events::{EventLog, EventRecord},
    identity::FolderKeys,
};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    BuilderCredentials, ChangePassword, FolderRef, Header, SecretAccess,
    Summary, Vault, VaultBuilder, VaultCommit, VaultFlags,
};
use sos_vfs as vfs;
use std::{borrow::Cow, collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "audit")]
use {
    sos_audit::{AuditData, AuditEvent},
    sos_backend::audit::append_audit_events,
    sos_core::events::EventKind,
};

use sos_core::{
    device::{DevicePublicKey, TrustedDevice},
    events::DeviceEvent,
};

use sos_backend::{compact::compact_folder, reducers::DeviceReducer};

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::FileEvent};

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

mod sync;

/// Client storage for folders loaded into memory and mirrored to disc.
pub struct ClientFileSystemStorage {
    /// Account identifier.
    pub(super) account_id: AccountId,

    /// Folders managed by this storage.
    pub(super) summaries: Vec<Summary>,

    /// Currently selected folder.
    pub(super) current: Option<Summary>,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

    /// Search index.
    #[cfg(feature = "search")]
    index: Option<AccountSearch>,

    /// Identity folder event log.
    ///
    /// This is a clone of the main identity folder
    /// event log and is defined here so we can
    /// get the commit state for synchronization.
    identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    account_log: Arc<RwLock<AccountEventLog>>,

    /// Folder event logs.
    folders: HashMap<VaultId, Folder>,

    /// Device event log.
    device_log: Arc<RwLock<DeviceEventLog>>,

    /// Reduced collection of devices.
    devices: IndexSet<TrustedDevice>,

    /// File event log.
    #[cfg(feature = "files")]
    file_log: Arc<RwLock<FileEventLog>>,

    /// External file manager.
    #[cfg(feature = "files")]
    external_file_manager: ExternalFileManager,
}

impl ClientFileSystemStorage {
    /// Create unauthenticated folder storage for client-side access.
    pub async fn new_unauthenticated(
        account_id: AccountId,
        paths: Paths,
    ) -> Result<Self> {
        paths.ensure().await?;

        let identity_log = Arc::new(RwLock::new(
            FolderEventLog::new_fs_folder(paths.identity_events()).await?,
        ));

        let account_log = Arc::new(RwLock::new(
            AccountEventLog::new_fs_account(paths.account_events()).await?,
        ));

        let device_log = Arc::new(RwLock::new(
            DeviceEventLog::new_fs_device(paths.device_events()).await?,
        ));

        #[cfg(feature = "files")]
        let file_log = Arc::new(RwLock::new(
            FileEventLog::new_fs_file(paths.file_events()).await?,
        ));

        let paths = Arc::new(paths);

        let mut storage = Self {
            account_id,
            summaries: Vec::new(),
            current: None,
            folders: Default::default(),
            paths: paths.clone(),
            identity_log,
            account_log,
            #[cfg(feature = "search")]
            index: None,
            device_log,
            devices: Default::default(),
            #[cfg(feature = "files")]
            file_log: file_log.clone(),
            #[cfg(feature = "files")]
            external_file_manager: ExternalFileManager::new(paths, file_log),
        };

        storage.load_folders().await?;

        Ok(storage)
    }

    /// Create folder storage for client-side access.
    pub async fn new_authenticated(
        account_id: AccountId,
        paths: Paths,
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
        let mut account_log =
            AccountEventLog::new_fs_account(log_file).await?;
        account_log.load_tree().await?;

        let (device_log, devices) =
            Self::initialize_device_log(&paths, device).await?;

        #[cfg(feature = "files")]
        let file_log =
            Arc::new(RwLock::new(Self::initialize_file_log(&paths).await?));

        let paths = Arc::new(paths);

        Ok(Self {
            account_id,
            summaries: Vec::new(),
            current: None,
            folders: Default::default(),
            paths: paths.clone(),
            identity_log,
            account_log: Arc::new(RwLock::new(account_log)),
            #[cfg(feature = "search")]
            index: Some(AccountSearch::new()),
            device_log: Arc::new(RwLock::new(device_log)),
            devices,
            #[cfg(feature = "files")]
            file_log: file_log.clone(),
            #[cfg(feature = "files")]
            external_file_manager: ExternalFileManager::new(paths, file_log),
        })
    }

    async fn initialize_device_log(
        paths: &Paths,
        device: TrustedDevice,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let log_file = paths.device_events();

        let mut event_log = DeviceEventLog::new_fs_device(log_file).await?;
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

    #[cfg(feature = "files")]
    async fn initialize_file_log(paths: &Paths) -> Result<FileEventLog> {
        let log_file = paths.file_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = FileEventLog::new_fs_file(log_file).await?;
        event_log.load_tree().await?;

        tracing::debug!(needs_init = %needs_init, "file_log");

        if needs_init {
            let files =
                sos_external_files::list_external_files(paths).await?;
            let events: Vec<FileEvent> =
                files.into_iter().map(|f| f.into()).collect();

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(event_log)
    }

    /// Initialize a folder from an event log.
    ///
    /// If an event log exists for the folder identifer
    /// it is replaced with the new event records.
    async fn initialize_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<(Folder, Vault)> {
        let vault_path = self.paths.vault_path(folder_id);

        // Prepare the vault file on disc
        let vault = {
            // We need a vault on disc to create the event log
            // so set a placeholder
            let vault: Vault = Default::default();
            let buffer = encode(&vault).await?;
            self.write_vault_file(folder_id, buffer).await?;

            let folder = Folder::new_fs(&vault_path).await?;
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
        let folder = Folder::new_fs(&vault_path).await?;
        let event_log = folder.event_log();
        let mut event_log = event_log.write().await;
        event_log.load_tree().await?;

        Ok((folder, vault))
    }

    /// Create new event log cache entries.
    async fn create_folder_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<()> {
        let vault_path = self.paths.vault_path(summary.id());
        let mut event_log = Folder::new_fs(&vault_path).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.clear().await?;

            let (_, events) = FolderReducer::split::<Error>(vault).await?;

            let mut records = Vec::with_capacity(events.len());
            for event in events.iter() {
                records.push(EventRecord::encode_event(event).await?);
            }
            if let (Some(creation_time), Some(event)) =
                (creation_time, records.get_mut(0))
            {
                event.set_time(creation_time.to_owned());
            }
            event_log.apply_records(records).await?;
        }

        self.folders.insert(*summary.id(), event_log);

        Ok(())
    }

    /// Refresh the in-memory vault from the contents
    /// of the current event log file.
    ///
    /// If a new access key is given and the target
    /// folder is the currently open folder then the
    /// in-memory `AccessPoint` is updated to use the new
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

        if let Some(folder) = self.folders.get_mut(summary.id()) {
            let keeper = folder.keeper_mut();
            keeper.lock();
            keeper.replace_vault(vault.clone(), false).await?;
            keeper.unlock(key).await?;
        }

        Ok(buffer)
    }

    /// Read the buffer for a vault from storage.
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
        write_exclusive(vault_path, buffer.as_ref()).await?;
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.folders.get(summary.id()).is_none() {
                self.create_folder_entry(summary, None, None).await?;
            }
        }
        Ok(())
    }

    /// Remove the local cache for a vault.
    fn remove_folder_entry(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current_folder().map(|c| *c.id());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_folder();
            }
        }

        // Remove from our cache of managed vaults
        self.folders.remove(summary.id());

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
        self.create_folder_entry(&summary, Some(vault), None)
            .await?;

        self.unlock_folder(summary.id(), &key).await?;

        Ok((buffer, key, summary))
    }

    /// Add a summary to this state.
    fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
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

        #[cfg(feature = "search")]
        if exists {
            if let Some(index) = self.index.as_mut() {
                // Clean entries from the search index
                index.remove_folder(summary.id()).await;
            }
        }

        self.write_vault_file(summary.id(), &buffer).await?;

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

        let event = vault.into_event().await?;

        // Initialize the local cache for event log
        self.create_folder_entry(&summary, Some(vault), creation_time)
            .await?;

        // Must ensure the folder is unlocked
        if let Some(key) = key {
            self.unlock_folder(summary.id(), key).await?;
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
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
        folder.clear().await?;
        folder.apply(events.iter().collect()).await?;

        Ok(buffer)
    }

    /// Load a vault by reducing it from the event log stored on disc.
    async fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault> {
        let folder = self
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(FolderReducer::new()
            .reduce(&*log_file)
            .await?
            .build(true)
            .await?)
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
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientSecretStorage for ClientFileSystemStorage {
    async fn create_secret(
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
                .folders
                .get_mut(summary.id())
                .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
            folder.create_secret(&secret_data).await?
        };

        #[cfg(feature = "files")]
        let file_events = {
            let (file_events, write_update) = self
                .external_file_manager
                .create_files(
                    &summary,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;

            if let Some((id, secret_data)) = write_update {
                // Update with new checksum(s)
                self.write_secret(&id, secret_data, false).await?;
            }

            file_events
        };

        let result = StorageChangeEvent {
            event,
            #[cfg(feature = "files")]
            file_events,
        };

        #[cfg(feature = "files")]
        self.external_file_manager
            .append_file_mutation_events(&result.file_events)
            .await?;

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) = (&self.index, index_doc) {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(result)
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'_, VaultCommit>, ReadEvent)>> {
        let folder = self
            .folders
            .get(folder_id)
            .ok_or(StorageError::CacheNotAvailable(*folder_id))?;
        Ok(folder.raw_secret(secret_id).await?)
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        let folder = self
            .folders
            .get(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
        let result = folder
            .read_secret(id)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    async fn update_secret(
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
            *secret_data.meta_mut() = meta;
            secret_data
        };

        let event = self
            .write_secret(secret_id, secret_data.clone(), true)
            .await?;

        // Must update the files before moving so checksums are correct
        #[cfg(feature = "files")]
        let file_events = {
            let folder = self.current_folder().ok_or(Error::NoOpenVault)?;
            let (file_events, write_update) = self
                .external_file_manager
                .update_files(
                    &folder,
                    &folder,
                    &old_secret_data,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;

            if let Some((id, secret_data)) = write_update {
                // Update with new checksum(s)
                self.write_secret(&id, secret_data, false).await?;
            }

            file_events
        };

        let result = StorageChangeEvent {
            event,
            #[cfg(feature = "files")]
            file_events,
        };

        #[cfg(feature = "files")]
        self.external_file_manager
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        secret_data.meta_mut().touch();

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
                .folders
                .get_mut(summary.id())
                .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
            let (_, meta, secret) = secret_data.into();
            folder
                .update_secret(id, meta, secret)
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

    async fn delete_secret(
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
                self.external_file_manager
                    .delete_files(
                        &folder,
                        &secret_data,
                        None,
                        &mut options.file_progress,
                    )
                    .await?
            },
        };

        #[cfg(feature = "files")]
        self.external_file_manager
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        let event = {
            let folder = self
                .folders
                .get_mut(summary.id())
                .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientFolderStorage for ClientFileSystemStorage {
    fn folders(&self) -> &HashMap<VaultId, Folder> {
        &self.folders
    }

    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder> {
        &mut self.folders
    }

    async fn create_folder(
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
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok((buf, key, summary, account_event))
    }

    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
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
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        let event = Event::Folder(account_event, write_event);
        Ok((event, summary))
    }

    async fn load_folders(&mut self) -> Result<&[Summary]> {
        let summaries = self.read_folders().await?;
        self.load_caches(&summaries).await?;
        self.summaries = summaries;
        Ok(self.list_folders())
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_folder_entry(summary)?;

        let mut events = Vec::new();

        #[cfg(feature = "files")]
        {
            let mut file_events = self
                .external_file_manager
                .delete_folder_files(summary.id())
                .await?;
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
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        events.insert(0, Event::Account(account_event));

        Ok(events)
    }

    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        let summary = self.find(|s| s.id() == folder_id).cloned();
        if let Some(summary) = summary {
            self.remove_folder_entry(&summary)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn list_folders(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    fn current_folder(&self) -> Option<Summary> {
        self.current.clone()
    }

    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        match vault {
            FolderRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            FolderRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent> {
        self.find(|s| s.id() == summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

        self.current = Some(summary.clone());
        Ok(ReadEvent::ReadVault)
    }

    fn close_folder(&mut self) {
        self.current = None;
    }

    async fn import_folder_patches(
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

            self.folders.insert(folder_id, folder);
            let summary = vault.summary().to_owned();
            self.add_summary(summary.clone());
        }
        Ok(())
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        {
            let folder = self
                .folders
                .get_mut(summary.id())
                .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
            let event_log = folder.event_log();
            let mut log_file = event_log.write().await;

            compact_folder(&mut *log_file).await?;
        }

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(summary, key).await?;

        let account_event =
            AccountEvent::CompactFolder(*summary.id(), buffer);

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(account_event)
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        let (mut folder, vault) =
            self.initialize_folder(folder_id, records).await?;

        // Unlock the folder
        folder.unlock(key).await?;
        self.folders.insert(*folder_id, folder);

        let summary = vault.summary().to_owned();
        self.add_summary(summary.clone());

        #[cfg(feature = "search")]
        if let Some(index) = self.index.as_mut() {
            // Ensure the imported secrets are in the search index
            index.add_vault(vault, key).await?;
        }

        Ok(summary)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_name(summary, name.as_ref())?;

        let folder = self
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

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
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(Event::Account(account_event))
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_flags(summary, flags.clone())?;

        let folder = self
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

        let event = folder.update_folder_flags(flags).await?;
        let event = Event::Write(*summary.id(), event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(event)
    }

    fn set_folder_name(
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

    fn set_folder_flags(
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

    async fn description(&self) -> Result<String> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.folders.get(summary.id()) {
            Ok(folder.description().await?)
        } else {
            Err(StorageError::CacheNotAvailable(*summary.id()).into())
        }
    }

    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.folders.get_mut(summary.id()) {
            Ok(folder.set_description(description).await?)
        } else {
            Err(StorageError::CacheNotAvailable(*summary.id()).into())
        }
    }

    async fn change_password(
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

        if let Some(folder) = self.folders.get_mut(vault.id()) {
            let keeper = folder.keeper_mut();
            keeper.unlock(&new_key).await?;
        }

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(new_key)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientFileSystemStorage {
    fn devices(&self) -> &IndexSet<TrustedDevice> {
        &self.devices
    }

    /// Set the collection of trusted devices.
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>) {
        self.devices = devices;
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        self.devices.iter().collect()
    }

    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        // Update the event log
        let mut event_log = self.device_log.write().await;
        event_log.apply(events.iter().collect()).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

        #[cfg(feature = "audit")]
        {
            let audit_events = events
                .iter()
                .filter_map(|event| match event {
                    DeviceEvent::Trust(device) => Some(AuditEvent::new(
                        Default::default(),
                        EventKind::TrustDevice,
                        *self.account_id(),
                        Some(AuditData::Device(*device.public_key())),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !audit_events.is_empty() {
                append_audit_events(audit_events.as_slice()).await?;
            }
        }

        Ok(())
    }

    async fn revoke_device(
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientAccountStorage for ClientFileSystemStorage {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        for (id, folder) in self.folders.iter_mut() {
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

    async fn lock(&mut self) {
        for (_, folder) in self.folders.iter_mut() {
            folder.lock();
        }
    }

    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        let folder = self
            .folders
            .get_mut(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        folder.unlock(key).await?;
        Ok(())
    }

    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        let folder = self
            .folders
            .get_mut(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        folder.lock();
        Ok(())
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        let create_account = Event::CreateAccount(account.account_id.into());

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &create_account).into();
            append_audit_events(&[audit_event]).await?;
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

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        let buffer = self.read_vault_file(id).await?;
        Ok(decode(&buffer).await?)
    }

    /// Get the history of events for a vault.
    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let folder = self
            .folders
            .get(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let mut records = Vec::new();

        let stream = log_file.event_stream(false).await;
        pin_mut!(stream);

        while let Some(result) = stream.next().await {
            let (record, event) = result?;
            let commit = *record.commit();
            let time = record.time().clone();
            records.push((commit, time, event));
        }

        Ok(records)
    }

    /// Commit state of the identity folder.
    async fn identity_state(&self) -> Result<CommitState> {
        let reader = self.identity_log.read().await;
        Ok(reader.tree().commit_state()?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let folder = self
            .folders
            .get(summary.id())
            .ok_or_else(|| StorageError::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().commit_state()?)
    }

    #[cfg(feature = "archive")]
    async fn restore_archive(
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
            let (vault, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;

            self.update_vault(vault.summary(), &vault, events).await?;

            // Refresh the in-memory and disc-based mirror
            let key = folder_keys
                .find(vault.id())
                .ok_or(Error::NoFolderPassword(*vault.id()))?;
            self.refresh_vault(vault.summary(), key).await?;
        }

        Ok(())
    }

    #[cfg(feature = "files")]
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    ) {
        self.external_file_manager.file_password = file_password;
    }

    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> &ExternalFileManager {
        &self.external_file_manager
    }

    #[cfg(feature = "files")]
    fn external_file_manager_mut(&mut self) -> &mut ExternalFileManager {
        &mut self.external_file_manager
    }

    #[cfg(feature = "search")]
    fn index(&self) -> Result<&AccountSearch> {
        self.index.as_ref().ok_or(Error::NoSearchIndex)
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        self.index.as_mut().ok_or(Error::NoSearchIndex)
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
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

    #[cfg(feature = "search")]
    async fn build_search_index(
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
                if let Some(folder) = self.folders.get_mut(summary.id()) {
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
}
