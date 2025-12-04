//! Server storage backed by a database.
use crate::{Error, Result, ServerAccountStorage};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    extract_vault, AccountEventLog, BackendTarget, DeviceEventLog,
    FolderEventLog, VaultWriter,
};
use sos_core::{
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode,
    events::{
        patch::{FolderDiff, FolderPatch},
        AccountEvent, EventLog,
    },
    AccountId, Paths, Recipient, VaultFlags, VaultId,
};
use sos_database::entity::{
    AccountEntity, AccountRow, FolderEntity, FolderRecord, FolderRow,
};
use sos_database::{async_sqlite::Client, entity::SharedFolderEntity};
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::{CreateSet, StorageEventLogs};
use sos_vault::{EncryptedEntry, Summary, Vault};
use sos_vfs as vfs;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use sos_backend::FileEventLog;

#[cfg(feature = "audit")]
use {sos_audit::AuditEvent, sos_backend::audit::append_audit_events};

/// Server folders loaded into memory and mirrored to the database.
pub struct ServerDatabaseStorage {
    /// Account identifier.
    pub(super) account_id: AccountId,

    /// Account database id.
    pub(super) account_row_id: i64,

    /// Directories for storage.
    pub(super) paths: Arc<Paths>,

    /// Database client.
    pub(super) client: Client,

    /// Backend target.
    pub(super) target: BackendTarget,

    /// Identity folder event log.
    pub(super) identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub(super) account_log: Arc<RwLock<AccountEventLog>>,

    /// Device event log.
    pub(super) device_log: Arc<RwLock<DeviceEventLog>>,

    /// File event log.
    #[cfg(feature = "files")]
    pub(super) file_log: Arc<RwLock<FileEventLog>>,

    /// Folder event logs.
    pub(super) folders: HashMap<VaultId, Arc<RwLock<FolderEventLog>>>,

    /// Reduced collection of devices.
    pub(super) devices: IndexSet<TrustedDevice>,
}

impl ServerDatabaseStorage {
    /// Create database storage for server-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new(
        mut target: BackendTarget,
        account_id: &AccountId,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        let (paths, client, account_row) = {
            let BackendTarget::Database(paths, client) = &mut target else {
                panic!("database backend expected");
            };
            debug_assert!(!paths.is_global());

            if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
                return Err(Error::NotDirectory(
                    paths.documents_dir().to_path_buf(),
                ));
            }

            let account_row =
                Self::lookup_account(client, account_id).await?;
            (paths, client, account_row)
        };

        let paths = paths.clone();
        let client = client.clone();

        let (device_log, devices) =
            Self::initialize_device_log(&target, account_id).await?;

        let mut event_log =
            AccountEventLog::new_account(target.clone(), account_id).await?;
        event_log.load_tree().await?;

        #[cfg(feature = "files")]
        let file_log = {
            let mut file_log =
                FileEventLog::new_file(target.clone(), account_id).await?;
            file_log.load_tree().await?;
            file_log
        };

        let mut storage = Self {
            account_id: *account_id,
            account_row_id: account_row.row_id,
            paths,
            client,
            target,
            identity_log,
            account_log: Arc::new(RwLock::new(event_log)),
            device_log: Arc::new(RwLock::new(device_log)),
            #[cfg(feature = "files")]
            file_log: Arc::new(RwLock::new(file_log)),
            folders: Default::default(),
            devices,
        };

        storage.load_folders().await?;

        Ok(storage)
    }

    async fn initialize_device_log(
        target: &BackendTarget,
        account_id: &AccountId,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let mut event_log =
            DeviceEventLog::new_device(target.clone(), account_id).await?;
        event_log.load_tree().await?;

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    /// Create new event log cache entries.
    async fn create_folder_entry(&mut self, id: &VaultId) -> Result<()> {
        let mut event_log = FolderEventLog::new_folder(
            self.target.clone(),
            &self.account_id,
            id,
        )
        .await?;
        event_log.load_tree().await?;
        self.folders.insert(*id, Arc::new(RwLock::new(event_log)));
        Ok(())
    }

    /// Remove a folder.
    async fn remove_vault_file(&self, folder_id: &VaultId) -> Result<()> {
        let folder_id = *folder_id;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.delete_folder(&folder_id)
            })
            .await
            .map_err(sos_database::Error::from)?;
        Ok(())
    }

    /// Create a new account.
    pub async fn initialize_account(
        target: &BackendTarget,
        account_id: &AccountId,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let BackendTarget::Database(paths, client) = &target else {
            panic!("database backend expected");
        };

        let vault = extract_vault(identity_patch.records())
            .await?
            .ok_or(Error::NoVaultEvent)?;

        let account_row =
            AccountRow::new_insert(account_id, vault.name().to_string())?;
        let folder_row = FolderRow::new_insert(&vault).await?;
        client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;

                // Create the account
                let account = AccountEntity::new(&tx);
                let account_id = account.insert(&account_row)?;

                // Create the folder
                let folder = FolderEntity::new(&tx);
                let folder_id =
                    folder.insert_folder(account_id, &folder_row)?;

                // Create the join
                account.insert_login_folder(account_id, folder_id)?;

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(sos_database::Error::from)?;

        let mut event_log = FolderEventLog::new_folder(
            BackendTarget::Database(paths.clone(), client.clone()),
            account_id,
            vault.id(),
        )
        .await?;
        event_log.clear().await?;
        event_log.patch_unchecked(identity_patch).await?;
        Ok(event_log)
    }

    async fn lookup_account(
        client: &mut Client,
        account_id: &AccountId,
    ) -> Result<AccountRow> {
        let account_id = *account_id;
        Ok(client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                account.find_one(&account_id)
            })
            .await
            .map_err(sos_database::Error::from)?)
    }
}

#[async_trait]
impl ServerAccountStorage for ServerDatabaseStorage {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn list_device_keys(&self) -> HashSet<&DevicePublicKey> {
        self.devices.iter().map(|d| d.public_key()).collect()
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    fn folders(&self) -> &HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &self.folders
    }

    fn folders_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &mut self.folders
    }

    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>) {
        self.devices = devices;
    }

    async fn rename_account(&self, name: &str) -> Result<()> {
        // Rename the folder (v1 logic)
        let account_id = self.account_row_id;
        let login_folder = self
            .client
            .conn_and_then(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.find_login_folder(account_id)
            })
            .await?;
        let login_folder = FolderRecord::from_row(login_folder).await?;

        let mut file =
            VaultWriter::new(self.target.clone(), login_folder.summary.id());
        file.set_vault_name(name.to_owned()).await?;

        // Update the accounts table (v2 logic)
        let account_id = self.account_row_id;
        let name = name.to_owned();
        self.client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                account.rename_account(account_id, &name)
            })
            .await?;

        Ok(())
    }

    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault> {
        Ok(FolderEntity::compute_folder_vault(&self.client, folder_id)
            .await?)
    }

    async fn write_vault(&self, vault: &Vault) -> Result<()> {
        let identity_id = *vault.id();
        let identity_row = FolderRow::new_update(vault).await?;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_folder(&identity_id, &identity_row)
            })
            .await?;
        Ok(())
    }

    /*
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
    */

    async fn write_login_vault(&self, vault: &Vault) -> Result<()> {
        AccountEntity::upsert_login_folder(
            &self.client,
            &self.account_id,
            vault,
        )
        .await?;
        Ok(())
    }

    async fn replace_folder(
        &self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<(FolderEventLog, Vault)> {
        let mut event_log = FolderEventLog::new_folder(
            BackendTarget::Database(self.paths.clone(), self.client.clone()),
            &self.account_id,
            folder_id,
        )
        .await?;
        event_log.replace_all_events(diff).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        FolderEntity::replace_all_secrets(
            self.client.clone(),
            folder_id,
            &vault,
        )
        .await?;

        Ok((event_log, vault))
    }

    async fn set_folder_flags(
        &self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<()> {
        let mut writer = VaultWriter::new(self.target.clone(), folder_id);
        writer.set_vault_flags(flags).await?;
        Ok(())
    }

    async fn import_account(
        &mut self,
        account_data: &CreateSet,
    ) -> Result<()> {
        let account_id = self.account_row_id;

        {
            let mut writer = self.account_log.write().await;
            writer.patch_unchecked(&account_data.account).await?;
        }

        {
            let mut writer = self.device_log.write().await;
            writer.patch_unchecked(&account_data.device).await?;
            let reducer = DeviceReducer::new(&*writer);
            self.devices = reducer.reduce().await?;
        }

        #[cfg(feature = "files")]
        {
            let mut writer = self.file_log.write().await;
            writer.patch_unchecked(&account_data.files).await?;
        }

        for (id, folder) in &account_data.folders {
            if let Some(vault) = extract_vault(folder.records()).await? {
                let folder_row = FolderRow::new_insert(&vault).await?;

                self.client
                    .conn(move |conn| {
                        let folder = FolderEntity::new(&conn);
                        folder.insert_folder(account_id, &folder_row)
                    })
                    .await
                    .map_err(sos_database::Error::from)?;

                let mut event_log = FolderEventLog::new_folder(
                    BackendTarget::Database(
                        self.paths.clone(),
                        self.client.clone(),
                    ),
                    &self.account_id,
                    id,
                )
                .await?;
                event_log.patch_unchecked(folder).await?;

                self.folders.insert(*id, Arc::new(RwLock::new(event_log)));
            }
        }

        Ok(())
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
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

        // Create a cache entry for each summary if it does not
        // already exist.
        for summary in &folders {
            // Ensure we don't overwrite existing data
            if !self.folders.contains_key(summary.id()) {
                self.create_folder_entry(summary.id()).await?;
            }
        }

        Ok(folders)
    }

    async fn import_folder(
        &mut self,
        id: &VaultId,
        buffer: &[u8],
    ) -> Result<()> {
        let exists = self.folders.contains_key(id);

        let vault: Vault = decode(buffer).await?;
        let (vault, events) = FolderReducer::split::<Error>(vault).await?;

        if id != vault.id() {
            return Err(Error::VaultIdentifierMismatch(*id, *vault.id()));
        }

        FolderEntity::upsert_folder_and_secrets(
            &self.client,
            self.account_row_id,
            &vault,
        )
        .await?;

        self.create_folder_entry(id).await?;

        {
            let event_log = self.folders.get_mut(id).unwrap();
            let mut event_log = event_log.write().await;
            event_log.clear().await?;
            event_log.apply(events.as_slice()).await?;
        }

        #[cfg(feature = "audit")]
        {
            let buffer = encode(&vault).await?;
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
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        // Remove from the database
        self.remove_vault_file(id).await?;

        // Remove local state
        self.folders.remove(id);

        #[cfg(feature = "files")]
        {
            let blob_folder = self.paths.into_file_folder_path(id);
            if vfs::try_exists(&blob_folder).await? {
                vfs::remove_dir_all(&blob_folder).await?;
            }
        }

        #[cfg(feature = "audit")]
        {
            let account_event = AccountEvent::DeleteFolder(*id);
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    async fn rename_folder(
        &mut self,
        id: &VaultId,
        name: &str,
    ) -> Result<()> {
        let mut access = VaultWriter::new(self.target.clone(), id);
        access.set_vault_name(name.to_owned()).await?;

        #[cfg(feature = "audit")]
        {
            let account_event =
                AccountEvent::RenameFolder(*id, name.to_owned());
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    async fn delete_account(&mut self) -> Result<()> {
        // Remove all account data from the database
        let account_id = self.account_id;
        self.client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                account.delete_account(&account_id)
            })
            .await
            .map_err(sos_database::Error::from)?;

        // Delete all file blobs for the account
        let blobs_dir = self.paths.into_files_dir();
        if vfs::try_exists(&blobs_dir).await? {
            vfs::remove_dir_all(&blobs_dir).await?;
        }

        Ok(())
    }

    async fn set_recipient(&mut self, recipient: Recipient) -> Result<()> {
        let account_id = self.account_id;
        self.client
            .conn_mut_and_then(move |conn| {
                let mut entity = SharedFolderEntity::new(conn);
                entity.upsert_recipient(account_id, recipient)
            })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl StorageEventLogs for ServerDatabaseStorage {
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
        let ids = self.folders.keys().copied().collect::<Vec<_>>();
        let mut output = IndexSet::new();
        // TODO: we could use a find_many() with "IN (id1, id2, ..)" here
        for id in ids {
            let row = self
                .client
                .conn(move |conn| {
                    let folder = FolderEntity::new(&conn);
                    folder.find_one(&id)
                })
                .await?;
            let record = FolderRecord::from_row(row).await?;
            output.insert(record.summary);
        }
        Ok(output)
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(Arc::clone(
            self.folders
                .get(id)
                .ok_or(sos_backend::StorageError::FolderNotFound(*id))?,
        ))
    }
}
