//! Storage backed by a database.
use crate::{
    ClientAccountStorage, ClientBaseStorage, ClientDeviceStorage,
    ClientEventLogStorage, ClientFolderStorage, ClientVaultStorage, Error,
    Result, traits::private::Internal,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use parking_lot::Mutex;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, Folder, FolderEventLog,
    StorageError, extract_vault,
};
use sos_core::{
    AccountId, Paths, SecretId, VaultFlags, VaultId, decode,
    device::TrustedDevice,
    encode,
    events::{DeviceEvent, Event, EventLog, ReadEvent},
};
use sos_database::{
    async_sqlite::Client,
    entity::{
        AccountEntity, AccountRow, FolderEntity, FolderRecord, FolderRow,
    },
};
use sos_login::Identity;
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::{CreateSet, StorageEventLogs};
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

    /// Backend target.
    target: BackendTarget,

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
    /// Create a new database account.
    pub(crate) async fn new_account(
        target: BackendTarget,
        account_id: &AccountId,
        account_name: String,
    ) -> Result<Self> {
        let (paths, client) = {
            debug_assert!(matches!(target, BackendTarget::Database(_, _)));
            let BackendTarget::Database(paths, client) = &target else {
                panic!("database backend expected");
            };
            debug_assert!(!paths.is_global());
            (paths, client)
        };

        // We have chosen to always have a FolderEventLog
        // for the identity folder so we don't need to keep
        // calling unwrap() on Option<FolderEventLog> so this
        // dance ensures we have a login folder ready before
        // we initialize the identity folder event log
        //
        // When import_account() is called (during device pairing)
        // this temporary identity log must be overwritten with the
        // correct folder information.
        let mut login_vault = Vault::default();
        login_vault.set_name(account_name.to_owned());
        *login_vault.flags_mut() = VaultFlags::IDENTITY;

        let account_row = AccountRow::new_insert(account_id, account_name)?;
        let folder_row = FolderRow::new_insert(&login_vault).await?;
        let account_row_id = client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let account = AccountEntity::new(&tx);
                let folder = FolderEntity::new(&tx);

                let account_id = account.insert(&account_row)?;
                let folder_id =
                    folder.insert_folder(account_id, &folder_row)?;
                account.insert_login_folder(account_id, folder_id)?;

                tx.commit()?;
                Ok(account_id)
            })
            .await
            .map_err(sos_backend::database::Error::from)?;

        let identity_log = FolderEventLog::new_folder(
            target.clone(),
            account_id,
            login_vault.id(),
        )
        .await?;

        let account_log =
            AccountEventLog::new_account(target.clone(), account_id).await?;

        let device_log =
            DeviceEventLog::new_device(target.clone(), account_id).await?;

        #[cfg(feature = "files")]
        let file_log =
            FileEventLog::new_file(target.clone(), account_id).await?;

        Ok(Self {
            account_id: *account_id,
            client: client.clone(),
            account_row_id,
            summaries: Vec::new(),
            current: Arc::new(Mutex::new(None)),
            folders: Default::default(),
            paths: paths.clone(),
            target,
            identity_log: Arc::new(RwLock::new(identity_log)),
            account_log: Arc::new(RwLock::new(account_log)),
            #[cfg(feature = "search")]
            index: None,
            device_log: Arc::new(RwLock::new(device_log)),
            devices: Default::default(),
            #[cfg(feature = "files")]
            file_log: Arc::new(RwLock::new(file_log)),
            #[cfg(feature = "files")]
            external_file_manager: None,
            authenticated: None,
        })
    }

    /// Create unauthenticated folder storage for client-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new_unauthenticated(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self> {
        let (paths, client) = {
            debug_assert!(matches!(target, BackendTarget::Database(_, _)));
            let BackendTarget::Database(paths, client) = &target else {
                panic!("database backend expected");
            };
            debug_assert!(!paths.is_global());
            (paths, client)
        };

        let (account_record, login_folder) =
            AccountEntity::find_account_with_login(client, account_id)
                .await?;

        let mut identity_log = FolderEventLog::new_folder(
            target.clone(),
            account_id,
            login_folder.summary.id(),
        )
        .await?;
        identity_log.load_tree().await?;

        let mut account_log =
            AccountEventLog::new_account(target.clone(), account_id).await?;
        account_log.load_tree().await?;

        let mut device_log =
            DeviceEventLog::new_device(target.clone(), account_id).await?;
        device_log.load_tree().await?;

        #[cfg(feature = "files")]
        let file_log = {
            let mut file_log =
                FileEventLog::new_file(target.clone(), account_id).await?;
            file_log.load_tree().await?;

            Arc::new(RwLock::new(file_log))
        };

        let mut storage = Self {
            account_id: *account_id,
            client: client.clone(),
            account_row_id: account_record.row_id,
            summaries: Vec::new(),
            current: Arc::new(Mutex::new(None)),
            folders: Default::default(),
            paths: paths.clone(),
            target,
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

    fn authenticated_user(&self) -> Option<&Identity> {
        self.authenticated.as_ref()
    }

    fn authenticated_user_mut(&mut self) -> Option<&mut Identity> {
        self.authenticated.as_mut()
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    fn backend_target(&self) -> &BackendTarget {
        &self.target
    }

    fn set_authenticated_user(
        &mut self,
        user: Option<Identity>,
        _: Internal,
    ) {
        self.authenticated = user;
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
            vault,
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
                folders.list_user_folders(account_id)
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
        // Must have a folder in the table for the event log to be valid
        FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            vault,
        )
        .await?;
        Ok(Folder::new(
            self.backend_target().clone(),
            &self.account_id,
            vault.id(),
        )
        .await?)
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
    async fn import_account(
        &mut self,
        account_data: &CreateSet,
    ) -> Result<()> {
        let account_id = self.account_row_id;

        {
            let mut event_log = self.account_log.write().await;
            event_log.patch_unchecked(&account_data.account).await?;
        }

        if let Some(vault) =
            extract_vault(account_data.identity.records()).await?
        {
            let mut event_log = self.identity_log.write().await;

            // Folder must be prepared before re-initializing
            // the event log
            AccountEntity::replace_login_folder(
                &mut self.client,
                &self.account_id,
                &vault,
            )
            .await?;

            // Re-initialize the event log ensuring we are using
            // the correct folder id for the new event log
            *event_log = FolderEventLog::new_folder(
                self.target.clone(),
                &self.account_id,
                vault.id(),
            )
            .await?;

            // Apply events to the log
            event_log.patch_unchecked(&account_data.identity).await?;

            // Ensure secrets reflect the log events
            let vault = FolderReducer::new()
                .reduce(&*event_log)
                .await?
                .build(true)
                .await?;

            self.write_login_vault(&vault, Internal).await?;
        }

        {
            let mut event_log = self.device_log.write().await;
            event_log.patch_unchecked(&account_data.device).await?;
            let reducer = DeviceReducer::new(&*event_log);
            self.devices = reducer.reduce().await?;
        }

        #[cfg(feature = "files")]
        {
            let mut event_log = self.file_log.write().await;
            event_log.patch_unchecked(&account_data.files).await?;
        }

        for (id, folder) in &account_data.folders {
            if let Some(vault) = extract_vault(folder.records()).await? {
                debug_assert_eq!(id, vault.id());

                // Prepare the folder relationship for the event log
                let folder_row = FolderRow::new_insert(&vault).await?;
                self.client
                    .conn(move |conn| {
                        let folder = FolderEntity::new(&conn);
                        folder.insert_folder(account_id, &folder_row)
                    })
                    .await
                    .map_err(sos_database::Error::from)?;

                let mut event_log = FolderEventLog::new_folder(
                    self.target.clone(),
                    &self.account_id,
                    id,
                )
                .await?;
                event_log.patch_unchecked(folder).await?;

                let vault = FolderReducer::new()
                    .reduce(&event_log)
                    .await?
                    .build(true)
                    .await?;

                FolderEntity::upsert_folder_and_secrets(
                    &self.client,
                    self.account_row_id,
                    &vault,
                )
                .await?;

                let summary = vault.summary().clone();
                let folder = Folder::from_vault_event_log(
                    &self.target,
                    vault,
                    event_log,
                )
                .await?;
                self.folders.insert(*id, folder);
                self.add_summary(summary, Internal);
            }
        }

        Ok(())
    }

    async fn list_secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<SecretId>> {
        let folder_id = *folder_id;
        let secret_ids = self
            .client
            .conn_and_then(move |conn| {
                let folder_entity = FolderEntity::new(&conn);
                folder_entity.list_secret_ids(&folder_id)
            })
            .await?;

        Ok(secret_ids)
    }

    async fn create_device_vault(
        &mut self,
        device_vault: &[u8],
    ) -> Result<()> {
        // Upsert the folder
        let vault: Vault = decode(device_vault).await?;
        let (folder_id, _) = FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            &vault,
        )
        .await?;

        // Create the join for the new device folder
        let account_row_id = self.account_row_id;
        self.client
            .conn(move |conn| {
                let account_entity = AccountEntity::new(&conn);
                account_entity.insert_device_folder(account_row_id, folder_id)
            })
            .await
            .map_err(sos_database::Error::from)?;

        Ok(())
    }

    async fn delete_account(&self) -> Result<Event> {
        let account_id = self.account_id;
        self.client
            .conn_mut(move |conn| {
                conn.execute("PRAGMA foreign_keys = ON", [])?;

                let tx = conn.transaction()?;
                let entity = AccountEntity::new(&tx);
                entity.delete_account(&account_id)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(sos_database::Error::from)?;

        // Delete external file blobs for the account
        let account_blobs = self.paths.into_files_dir();
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
        let mut event_log = DeviceEventLog::new_device(
            BackendTarget::Database(self.paths.clone(), self.client.clone()),
            &self.account_id,
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
        let mut file_log = FileEventLog::new_file(
            BackendTarget::Database(self.paths.clone(), self.client.clone()),
            &self.account_id,
        )
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
        Ok(folders.iter().cloned().collect())
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
