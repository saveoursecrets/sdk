//! Storage backed by a database.
use crate::{
    files::ExternalFileManager, traits::private::Internal,
    ClientAccountStorage, ClientBaseStorage, ClientDeviceStorage,
    ClientFolderStorage, ClientVaultStorage, Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use parking_lot::Mutex;
use sos_backend::{
    AccountEventLog, DeviceEventLog, Folder, FolderEventLog, StorageError,
};
use sos_core::{
    crypto::AccessKey,
    device::TrustedDevice,
    encode,
    events::{AccountEvent, DeviceEvent, EventLog, ReadEvent, WriteEvent},
    AccountId, AuthenticationError, Paths, VaultId,
};
use sos_database::{
    async_sqlite::Client,
    entity::{AccountEntity, FolderEntity, FolderRecord},
};
use sos_login::{FolderKeys, Identity};
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::StorageEventLogs;
use sos_vault::{ChangePassword, SecretAccess, Summary, Vault, VaultFlags};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "files")]
use sos_backend::FileEventLog;

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
    external_file_manager: ExternalFileManager,
}

impl ClientDatabaseStorage {
    /// Create unauthenticated folder storage for client-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new_unauthenticated(
        paths: &Paths,
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
            external_file_manager: ExternalFileManager::new(
                paths, file_log, None,
            ),
            authenticated: None,
        };

        storage.load_folders().await?;

        Ok(storage)
    }

    async fn initialize_device_log(
        device: TrustedDevice,
        account_id: &AccountId,
        client: &Client,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let mut event_log =
            DeviceEventLog::new_db_device(client.clone(), *account_id)
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
            event_log.apply(vec![&event]).await?;
        }

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
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
    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault> {
        Ok(FolderEntity::compute_folder_vault(&self.client, folder_id)
            .await?)
    }

    async fn write_vault(&self, vault: &Vault) -> Result<Vec<u8>> {
        let buffer = encode(vault).await?;
        FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            &vault,
        )
        .await?;
        Ok(buffer)
    }

    async fn remove_vault(&self, folder_id: &VaultId) -> Result<()> {
        todo!("impl remove_vault for db");
    }

    async fn read_folders(&self) -> Result<Vec<Summary>> {
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

    fn current_folder(&self) -> Option<Summary> {
        let current = self.current.lock();
        current.clone()
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

    async fn new_folder(&self, folder_id: &VaultId) -> Result<Folder> {
        Ok(
            Folder::new_db(self.client.clone(), self.account_id, *folder_id)
                .await?,
        )
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
            Err(StorageError::FolderNotFound(*summary.id()).into())
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
            Err(StorageError::FolderNotFound(*summary.id()).into())
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
            let access_point = folder.access_point();
            let mut access_point = access_point.lock().await;
            access_point.unlock(&new_key).await?;
        }

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(new_key)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientDatabaseStorage {
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

    fn drop_authenticated_state(&mut self, _: Internal) {
        #[cfg(feature = "search")]
        {
            self.index = None;
        }
        self.authenticated = None;
    }

    async fn authenticate(
        &mut self,
        authenticated_user: Identity,
    ) -> Result<()> {
        let identity_log = authenticated_user.identity()?.event_log();
        let device = authenticated_user
            .identity()?
            .devices()?
            .current_device(None);

        let (device_log, devices) = Self::initialize_device_log(
            device,
            &self.account_id,
            &self.client,
        )
        .await?;

        #[cfg(feature = "search")]
        {
            self.index = Some(AccountSearch::new());
        }

        #[cfg(feature = "files")]
        {
            let file_password =
                authenticated_user.find_file_encryption_password().await?;
            self.external_file_manager = ExternalFileManager::new(
                self.paths.clone(),
                self.file_log.clone(),
                Some(file_password),
            );
        }

        self.identity_log = identity_log;
        self.device_log = Arc::new(RwLock::new(device_log));
        self.devices = devices;
        self.authenticated = Some(authenticated_user);

        Ok(())
    }

    async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        self.authenticated
            .as_ref()
            .ok_or(AuthenticationError::NotAuthenticated)?;

        // Update the identity vault
        let buffer = encode(&vault).await?;

        let (folder_id, _) = FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            &vault,
        )
        .await?;

        todo!("update identity folder join!!!");

        // Update the events for the identity vault
        let user = self
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        let identity = user.identity()?;
        let event_log = identity.event_log();
        let mut event_log = event_log.write().await;
        event_log.clear().await?;

        let (_, events) = FolderReducer::split::<Error>(vault).await?;
        event_log.apply(events.iter().collect()).await?;

        Ok(AccountEvent::UpdateIdentity(buffer))
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
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
    fn external_file_manager(&self) -> &ExternalFileManager {
        &self.external_file_manager
    }

    #[cfg(feature = "files")]
    fn external_file_manager_mut(&mut self) -> &mut ExternalFileManager {
        &mut self.external_file_manager
    }

    #[cfg(feature = "search")]
    fn index(&self) -> Option<&AccountSearch> {
        self.index.as_ref()
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Option<&mut AccountSearch> {
        self.index.as_mut()
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
