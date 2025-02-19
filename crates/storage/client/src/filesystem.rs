//! Storage backed by the filesystem.
use crate::{
    traits::private::Internal, ClientAccountStorage, ClientBaseStorage,
    ClientDeviceStorage, ClientEventLogStorage, ClientFolderStorage,
    ClientVaultStorage, Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use parking_lot::Mutex;
use sos_backend::{
    write_exclusive, AccountEventLog, DeviceEventLog, Folder, FolderEventLog,
    StorageError,
};
use sos_core::{
    constants::VAULT_EXT,
    decode,
    device::TrustedDevice,
    encode,
    events::{DeviceEvent, EventLog, ReadEvent},
    AccountId, Paths, VaultId,
};
use sos_login::Identity;
use sos_reducers::DeviceReducer;
use sos_sync::StorageEventLogs;
use sos_vault::{Header, Summary, Vault};
use sos_vfs as vfs;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {
    crate::files::ExternalFileManager, sos_backend::FileEventLog,
    sos_core::events::FileEvent,
};

#[cfg(feature = "search")]
use sos_search::AccountSearch;

/// Client storage for folders loaded into memory and mirrored to disc.
pub struct ClientFileSystemStorage {
    /// Account identifier.
    account_id: AccountId,

    /// Folders managed by this storage.
    summaries: Vec<Summary>,

    /// Directories for file storage.
    paths: Arc<Paths>,

    // Use interior mutability so all the account functions
    // that accept an optional folder when reading do not need
    // to be mutable.
    /// Currently selected folder.
    current: Arc<Mutex<Option<Summary>>>,

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

    /// Account information after a successful
    /// sign in.
    authenticated: Option<Identity>,

    /// Search index.
    #[cfg(feature = "search")]
    index: Option<AccountSearch>,

    /// File event log.
    #[cfg(feature = "files")]
    file_log: Arc<RwLock<FileEventLog>>,

    /// External file manager.
    #[cfg(feature = "files")]
    external_file_manager: Option<ExternalFileManager>,
}

impl ClientFileSystemStorage {
    /// Create unauthenticated folder storage for client-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new_unauthenticated(
        paths: Paths,
        account_id: &AccountId,
    ) -> Result<Self> {
        debug_assert!(!paths.is_global());

        paths.ensure().await?;

        let mut identity_log =
            FolderEventLog::new_fs_folder(paths.identity_events()).await?;
        identity_log.load_tree().await?;

        let mut account_log =
            AccountEventLog::new_fs_account(paths.account_events()).await?;
        account_log.load_tree().await?;

        let mut device_log =
            DeviceEventLog::new_fs_device(paths.device_events()).await?;
        device_log.load_tree().await?;

        #[cfg(feature = "files")]
        let file_log = {
            let mut file_log =
                FileEventLog::new_fs_file(paths.file_events()).await?;
            file_log.load_tree().await?;
            Arc::new(RwLock::new(file_log))
        };

        let paths = Arc::new(paths);

        let mut storage = Self {
            account_id: *account_id,
            summaries: Vec::new(),
            current: Arc::new(Mutex::new(None)),
            folders: Default::default(),
            paths: paths.clone(),
            identity_log: Arc::new(RwLock::new(identity_log)),
            account_log: Arc::new(RwLock::new(account_log)),
            #[cfg(feature = "search")]
            index: None,
            device_log: Arc::new(RwLock::new(device_log)),
            devices: Default::default(),
            #[cfg(feature = "files")]
            file_log: file_log.clone(),
            #[cfg(feature = "files")]
            external_file_manager: None,
            authenticated: None,
        };

        storage.load_folders().await?;

        Ok(storage)
    }
}

impl ClientBaseStorage for ClientFileSystemStorage {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientVaultStorage for ClientFileSystemStorage {
    async fn write_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>> {
        let buffer = encode(vault).await?;
        write_exclusive(self.paths.vault_path(vault.id()), &buffer).await?;
        Ok(buffer)
    }

    async fn write_login_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>> {
        let buffer = encode(vault).await?;
        write_exclusive(self.paths().identity_vault(), &buffer).await?;
        Ok(buffer)
    }

    async fn remove_vault(
        &self,
        folder_id: &VaultId,
        _: Internal,
    ) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.paths.vault_path(folder_id);
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Remove the local event log file
        let event_log_path = self.paths.event_log_path(folder_id);
        if vfs::try_exists(&event_log_path).await? {
            vfs::remove_file(&event_log_path).await?;
        }
        Ok(())
    }

    async fn read_vaults(&self, _: Internal) -> Result<Vec<Summary>> {
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

    fn summaries(&self, _: Internal) -> &Vec<Summary> {
        &self.summaries
    }

    fn summaries_mut(&mut self, _: Internal) -> &mut Vec<Summary> {
        &mut self.summaries
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

    async fn new_folder(&self, vault: &Vault, _: Internal) -> Result<Folder> {
        let vault_path = self.paths.vault_path(vault.id());
        Ok(Folder::new_fs(&vault_path).await?)
    }

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        let vault_path = self.paths.vault_path(id);
        let buffer = vfs::read(vault_path).await?;
        Ok(decode(&buffer).await?)
    }

    async fn read_login_vault(&self) -> Result<Vault> {
        let vault_path = self.paths.identity_vault();
        let buffer = vfs::read(vault_path).await?;
        Ok(decode(&buffer).await?)
    }

    fn current_folder(&self) -> Option<Summary> {
        let current = self.current.lock();
        current.clone()
    }

    fn open_folder(&self, folder_id: &VaultId) -> Result<ReadEvent> {
        let summary = self
            .find(|s| s.id() == folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;

        let mut current = self.current.lock();
        *current = Some(summary.clone());

        Ok(ReadEvent::ReadVault)
    }

    fn close_folder(&self) {
        let mut current = self.current.lock();
        *current = None;
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientFileSystemStorage {
    fn devices(&self) -> &IndexSet<TrustedDevice> {
        &self.devices
    }

    /// Set the collection of trusted devices.
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>, _: Internal) {
        self.devices = devices;
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        self.devices.iter().collect()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientAccountStorage for ClientFileSystemStorage {
    fn authenticated_user(&self) -> Option<&Identity> {
        self.authenticated.as_ref()
    }

    fn authenticated_user_mut(&mut self) -> Option<&mut Identity> {
        self.authenticated.as_mut()
    }

    fn set_authenticated_user(
        &mut self,
        user: Option<Identity>,
        _: Internal,
    ) {
        self.authenticated = user;
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> Option<&ExternalFileManager> {
        self.external_file_manager.as_ref()
    }

    #[cfg(feature = "files")]
    fn external_file_manager_mut(
        &mut self,
    ) -> Option<&mut ExternalFileManager> {
        self.external_file_manager.as_mut()
    }

    #[cfg(feature = "files")]
    fn set_external_file_manager(
        &mut self,
        file_manager: Option<ExternalFileManager>,
        _: Internal,
    ) {
        self.external_file_manager = file_manager;
    }

    #[cfg(feature = "search")]
    fn search_index(&self) -> Option<&AccountSearch> {
        self.index.as_ref()
    }

    #[cfg(feature = "search")]
    fn search_index_mut(&mut self) -> Option<&mut AccountSearch> {
        self.index.as_mut()
    }

    #[cfg(feature = "search")]
    fn set_search_index(
        &mut self,
        index: Option<AccountSearch>,
        _: Internal,
    ) {
        self.index = index;
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientEventLogStorage for ClientFileSystemStorage {
    async fn initialize_device_log(
        &self,
        device: TrustedDevice,
        _: Internal,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let log_file = self.paths.device_events();

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
            event_log.apply(&[event.clone()]).await?;
        }

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(&self, _: Internal) -> Result<FileEventLog> {
        let log_file = self.paths.file_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = FileEventLog::new_fs_file(log_file).await?;
        event_log.load_tree().await?;

        tracing::debug!(needs_init = %needs_init, "file_log");

        if needs_init {
            let files =
                sos_external_files::list_external_files(&self.paths).await?;
            let events: Vec<FileEvent> =
                files.into_iter().map(|f| f.into()).collect();

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.as_slice()).await?;
        }

        Ok(event_log)
    }

    fn set_identity_log(
        &mut self,
        log: Arc<RwLock<FolderEventLog>>,
        _: Internal,
    ) {
        self.identity_log = log;
    }

    fn set_device_log(
        &mut self,
        log: Arc<RwLock<DeviceEventLog>>,
        _: Internal,
    ) {
        self.device_log = log;
    }

    #[cfg(feature = "files")]
    fn set_file_log(&mut self, log: Arc<RwLock<FileEventLog>>, _: Internal) {
        self.file_log = log;
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientFileSystemStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(self.identity_log.clone())
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(self.account_log.clone())
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(self.device_log.clone())
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(self.file_log.clone())
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let folders = self.list_folders();
        Ok(folders.into_iter().cloned().collect())
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let folder = self
            .folders
            .get(id)
            .ok_or(StorageError::FolderNotFound(*id))?;
        Ok(folder.event_log())
    }
}
