//! Storage backed by a database.
use crate::{
    traits::private::Internal, ClientAccountStorage, ClientBaseStorage,
    ClientDeviceStorage, ClientEventLogStorage, ClientFolderStorage,
    ClientVaultStorage, Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use parking_lot::Mutex;
use sos_backend::{
    AccountEventLog, DeviceEventLog, Folder, FolderEventLog, StorageError,
};
use sos_core::{
    device::TrustedDevice,
    encode,
    events::{DeviceEvent, Event, EventLog, ReadEvent},
    AccountId, Paths, VaultId,
};
use sos_database::{
    async_sqlite::Client,
    entity::{AccountEntity, FolderEntity, FolderRecord},
};
use sos_login::Identity;
use sos_reducers::DeviceReducer;
use sos_sync::StorageEventLogs;
use sos_vault::{Summary, Vault};
use sos_vfs as vfs;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {crate::files::ExternalFileManager, sos_backend::FileEventLog};

#[cfg(feature = "search")]
use sos_search::AccountSearch;

/// Client storage for folders loaded into memory
/// and stored in a database.
pub struct ClientDatabaseStorage {
    /// Account identifier.
    account_id: AccountId,

    /// Folders managed by this storage.
    summaries: Vec<Summary>,

    /// Directories for file storage.
    paths: Arc<Paths>,

    /// Database client.
    client: Client,

    /// Account row identifier.
    account_row_id: i64,

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

impl ClientDatabaseStorage {
    /// Create unauthenticated folder storage for client-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new_unauthenticated(
        paths: Paths,
        account_id: &AccountId,
        client: Client,
    ) -> Result<Self> {
        debug_assert!(!paths.is_global());

        let (account_record, login_folder) =
            AccountEntity::find_account_with_login(&client, account_id)
                .await?;

        let mut identity_log = FolderEventLog::new_db_folder(
            client.clone(),
            *account_id,
            *login_folder.summary.id(),
        )
        .await?;
        identity_log.load_tree().await?;

        let mut account_log =
            AccountEventLog::new_db_account(client.clone(), *account_id)
                .await?;
        account_log.load_tree().await?;

        let mut device_log =
            DeviceEventLog::new_db_device(client.clone(), *account_id)
                .await?;
        device_log.load_tree().await?;

        #[cfg(feature = "files")]
        let file_log = {
            let mut file_log =
                FileEventLog::new_db_file(client.clone(), *account_id)
                    .await?;
            file_log.load_tree().await?;

            Arc::new(RwLock::new(file_log))
        };

        let paths = Arc::new(paths.clone());

        let mut storage = Self {
            account_id: *account_id,
            client,
            account_row_id: account_record.row_id,
            summaries: Vec::new(),
            current: Arc::new(Mutex::new(None)),
            folders: Default::default(),
            paths,
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

impl ClientBaseStorage for ClientDatabaseStorage {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientVaultStorage for ClientDatabaseStorage {
    async fn write_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>> {
        FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            &vault,
        )
        .await?;
        Ok(encode(vault).await?)
    }

    async fn write_login_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>> {
        AccountEntity::upsert_login_folder(
            &self.client,
            &self.account_id,
            vault,
        )
        .await?;
        Ok(encode(vault).await?)
    }

    async fn remove_vault(
        &self,
        folder_id: &VaultId,
        _: Internal,
    ) -> Result<()> {
        let folder_id = *folder_id;
        self.client
            .conn(move |conn| {
                let folder_entity = FolderEntity::new(&conn);
                folder_entity.delete_folder(&folder_id)
            })
            .await
            .map_err(sos_database::Error::from)?;
        Ok(())
    }

    async fn read_vaults(&self, _: Internal) -> Result<Vec<Summary>> {
        let account_id = self.account_row_id;
        let rows = self
            .client
            .conn_and_then(move |conn| {
                let folders = FolderEntity::new(&conn);
                Ok::<_, sos_database::Error>(
                    folders.list_user_folders(account_id)?,
                )
            })
            .await?;
        let mut folders = Vec::new();
        for row in rows {
            let record = FolderRecord::from_row(row).await?;
            folders.push(record.summary);
        }
        Ok(folders)
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
impl ClientFolderStorage for ClientDatabaseStorage {
    fn folders(&self) -> &HashMap<VaultId, Folder> {
        &self.folders
    }

    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder> {
        &mut self.folders
    }

    async fn new_folder(&self, vault: &Vault, _: Internal) -> Result<Folder> {
        let folder_id = *vault.id();
        // Must have a folder in the table for the event log to be valid
        FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            vault,
        )
        .await?;
        Ok(
            Folder::new_db(self.client.clone(), self.account_id, folder_id)
                .await?,
        )
    }

    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault> {
        Ok(FolderEntity::compute_folder_vault(&self.client, folder_id)
            .await?)
    }

    async fn read_login_vault(&self) -> Result<Vault> {
        let account_row_id = self.account_row_id;
        let folder_row = self
            .client
            .conn_and_then(move |conn| {
                let folder_entity = FolderEntity::new(&conn);
                folder_entity.find_login_folder(account_row_id)
            })
            .await?;
        let record = FolderRecord::from_row(folder_row).await?;
        Ok(FolderEntity::compute_folder_vault(
            &self.client,
            record.summary.id(),
        )
        .await?)
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
impl ClientDeviceStorage for ClientDatabaseStorage {
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
impl ClientAccountStorage for ClientDatabaseStorage {
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

    async fn delete_account(&self) -> Result<Event> {
        let account_id = self.account_id;
        self.client
            .conn(move |conn| {
                let entity = AccountEntity::new(&conn);
                entity.delete_account(&account_id)
            })
            .await
            .map_err(sos_database::Error::from)?;

        // Delete external file blobs for the account
        let account_blobs = self.paths.blobs_account_dir();
        if vfs::try_exists(&account_blobs).await? {
            vfs::remove_dir_all(&account_blobs).await?;
        }

        Ok(Event::DeleteAccount(self.account_id))
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
impl ClientEventLogStorage for ClientDatabaseStorage {
    async fn initialize_device_log(
        &self,
        device: TrustedDevice,
        _: Internal,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let mut event_log = DeviceEventLog::new_db_device(
            self.client.clone(),
            self.account_id,
        )
        .await?;
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
            event_log.apply(&[event]).await?;
        }

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    #[cfg(feature = "files")]
    async fn initialize_file_log(&self, _: Internal) -> Result<FileEventLog> {
        let mut file_log =
            FileEventLog::new_db_file(self.client.clone(), self.account_id)
                .await?;
        file_log.load_tree().await?;
        Ok(file_log)
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
impl StorageEventLogs for ClientDatabaseStorage {
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
