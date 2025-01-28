//! Server storage backed by a database.
use crate::{Error, Result, ServerAccountStorage};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::reducers::{DeviceReducer, FolderReducer};
use sos_backend::VaultWriter;
use sos_backend::{
    AccountEventLog, DeviceEventLog, FileEventLog, FolderEventLog,
};
use sos_core::events::{
    patch::FolderPatch, AccountEvent, EventLog, FileEvent,
};
use sos_core::{
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode, AccountId, Paths, VaultId,
};
use sos_database::async_sqlite::Client;
use sos_database::db::{
    AccountEntity, AccountRow, FolderEntity, FolderRecord, FolderRow,
};
use sos_sdk::events::{EventRecord, WriteEvent};
use sos_sync::{CreateSet, ForceMerge, MergeOutcome, UpdateSet};
use sos_vault::{EncryptedEntry, Summary, Vault};
use sos_vfs as vfs;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "audit")]
use {sos_audit::AuditEvent, sos_backend::audit::append_audit_events};

mod sync;

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

    /// Identity folder event log.
    pub(super) identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub(super) account_log: Arc<RwLock<AccountEventLog>>,

    /// Device event log.
    pub(super) device_log: Arc<RwLock<DeviceEventLog>>,

    /// File event log.
    pub(super) file_log: Arc<RwLock<FileEventLog>>,

    /// Folder event logs.
    pub(super) folders: HashMap<VaultId, Arc<RwLock<FolderEventLog>>>,

    /// Reduced collection of devices.
    pub(super) devices: IndexSet<TrustedDevice>,
}

impl ServerDatabaseStorage {
    /// Create database storage for server-side access.
    pub async fn new(
        client: Client,
        account_id: AccountId,
        data_dir: Option<PathBuf>,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir().map_err(|_| Error::NoCache)?
        };

        let dirs = Paths::new_server(data_dir, account_id.to_string());
        Self::new_client(client, Arc::new(dirs), account_id, identity_log)
            .await
    }

    /// Create new storage backed by a database file on disc.
    async fn new_client(
        mut client: Client,
        paths: Arc<Paths>,
        account_id: AccountId,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            )
            .into());
        }

        paths.ensure().await?;

        let account_row =
            Self::lookup_account(&mut client, &account_id).await?;

        let mut event_log =
            AccountEventLog::new_db_account(client.clone(), account_id)
                .await?;
        event_log.load_tree().await?;
        let account_log = Arc::new(RwLock::new(event_log));

        let (device_log, devices) =
            Self::initialize_device_log(&client, &account_id).await?;

        let file_log =
            Self::initialize_file_log(&*paths, &client, &account_id).await?;

        Ok(Self {
            account_id,
            account_row_id: account_row.row_id,
            paths,
            client,
            identity_log,
            account_log,
            device_log: Arc::new(RwLock::new(device_log)),
            file_log: Arc::new(RwLock::new(file_log)),
            folders: Default::default(),
            devices,
        })
    }

    async fn initialize_device_log(
        client: &Client,
        account_id: &AccountId,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let mut event_log =
            DeviceEventLog::new_db_device(client.clone(), *account_id)
                .await?;
        event_log.load_tree().await?;

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    async fn initialize_file_log(
        paths: &Paths,
        client: &Client,
        account_id: &AccountId,
    ) -> Result<FileEventLog> {
        use sos_external_files::list_external_files;

        let mut event_log =
            FileEventLog::new_db_file(client.clone(), *account_id).await?;

        // todo!("determine if file events need initializing");

        Ok(event_log)

        /*
        tracing::debug!(needs_init = %needs_init, "file_log");

        if needs_init {
            let files = list_external_files(paths).await?;
            let events: Vec<FileEvent> =
                files.into_iter().map(|f| f.into()).collect();

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(event_log)
        */
    }

    /// Create new event log cache entries.
    async fn create_folder_entry(&mut self, id: &VaultId) -> Result<()> {
        let mut event_log = FolderEventLog::new_db_folder(
            self.client.clone(),
            self.account_id.clone(),
            *id,
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
        client: &mut Client,
        account_id: &AccountId,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let vault = Self::extract_vault(identity_patch.records())
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

        let mut event_log = FolderEventLog::new_db_folder(
            client.clone(),
            *account_id,
            *vault.id(),
        )
        .await?;
        event_log.clear().await?;
        event_log.patch_unchecked(identity_patch).await?;
        Ok(event_log)
    }

    fn folders_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &mut self.folders
    }

    async fn lookup_account(
        client: &mut Client,
        account_id: &AccountId,
    ) -> Result<AccountRow> {
        let account_id = *account_id;
        Ok(client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                Ok(account.find_one(&account_id)?)
            })
            .await
            .map_err(sos_database::Error::from)?)
    }

    /// Extract a vault from the first write event in
    /// a collection of records.
    async fn extract_vault(records: &[EventRecord]) -> Result<Option<Vault>> {
        let first_record = records.get(0);
        Ok(if let Some(record) = first_record {
            let event: WriteEvent = record.decode_event().await?;
            let WriteEvent::CreateVault(buf) = event else {
                return Err(sos_core::Error::CreateEventMustBeFirst.into());
            };
            let vault: Vault = decode(&buf).await?;
            Some(vault)
        } else {
            None
        })
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

        {
            let mut writer = self.file_log.write().await;
            writer.patch_unchecked(&account_data.files).await?;
        }

        for (id, folder) in &account_data.folders {
            if let Some(vault) = Self::extract_vault(folder.records()).await?
            {
                let folder_row = FolderRow::new_insert(&vault).await?;

                self.client
                    .conn(move |conn| {
                        let folder = FolderEntity::new(&conn);
                        folder.insert_folder(account_id, &folder_row)
                    })
                    .await
                    .map_err(sos_database::Error::from)?;

                let mut event_log = FolderEventLog::new_db_folder(
                    self.client.clone(),
                    self.account_id.clone(),
                    *id,
                )
                .await?;
                event_log.patch_unchecked(folder).await?;

                self.folders_mut()
                    .insert(*id, Arc::new(RwLock::new(event_log)));
            }
        }

        Ok(())
    }

    async fn update_account(
        &mut self,
        mut update_set: UpdateSet,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        if let Some(diff) = update_set.identity.take() {
            self.force_merge_identity(diff, outcome).await?;
        }

        if let Some(diff) = update_set.account.take() {
            self.force_merge_account(diff, outcome).await?;
        }

        if let Some(diff) = update_set.device.take() {
            self.force_merge_device(diff, outcome).await?;
        }

        if let Some(diff) = update_set.files.take() {
            self.force_merge_files(diff, outcome).await?;
        }

        for (id, folder) in update_set.folders {
            self.force_merge_folder(&id, folder, outcome).await?;
        }

        Ok(())
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
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
            folders.push(FolderRecord::from_row(row).await?);
        }

        let folders =
            folders.into_iter().map(|f| f.summary).collect::<Vec<_>>();

        // Create a cache entry for each summary if it does not
        // already exist.
        for summary in &folders {
            // Ensure we don't overwrite existing data
            if self.folders.get(summary.id()).is_none() {
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
        let exists = self.folders.get(id).is_some();

        let vault: Vault = decode(buffer).await?;
        let (vault, events) = FolderReducer::split::<Error>(vault).await?;

        if id != vault.id() {
            return Err(
                Error::VaultIdentifierMismatch(*id, *vault.id()).into()
            );
        }

        let vault_path = self.paths.vault_path(id);
        let buffer = encode(&vault).await?;
        vfs::write(vault_path, &buffer).await?;

        self.create_folder_entry(id).await?;

        {
            let event_log = self.folders.get_mut(id).unwrap();
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
            let blob_folder = self.paths.blob_folder_location(&id);
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
        let mut access = VaultWriter::new_db(self.client.clone(), *id);
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
        let account_id = self.account_id.clone();
        self.client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                account.delete_account(&account_id)
            })
            .await
            .map_err(sos_database::Error::from)?;

        // Delete all file blobs for the account
        let blobs_dir = self.paths.blobs_account_dir();
        if vfs::try_exists(&blobs_dir).await? {
            vfs::remove_dir_all(&blobs_dir).await?;
        }

        Ok(())
    }
}
