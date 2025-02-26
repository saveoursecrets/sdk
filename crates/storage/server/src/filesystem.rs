//! Server storage backed by the filesystem.
use crate::{Error, Result, ServerAccountStorage};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, FolderEventLog,
    VaultWriter,
};
use sos_core::{
    constants::VAULT_EXT,
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode,
    events::{
        patch::{FolderDiff, FolderPatch},
        AccountEvent, EventLog,
    },
    AccountId, Paths, VaultFlags, VaultId,
};
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::{CreateSet, StorageEventLogs};
use sos_vault::{EncryptedEntry, Header, Summary, Vault};
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

/// Server folders loaded into memory and mirrored to disc.
pub struct ServerFileStorage {
    /// Account identifier.
    pub(super) account_id: AccountId,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

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

impl ServerFileStorage {
    /// Create folder storage for server-side access.
    ///
    /// Events are loaded into memory.
    pub async fn new(
        target: BackendTarget,
        account_id: &AccountId,
        identity_log: Arc<RwLock<FolderEventLog>>,
    ) -> Result<Self> {
        debug_assert!(matches!(target, BackendTarget::FileSystem(_)));
        let BackendTarget::FileSystem(paths) = &target else {
            panic!("filesystem backend expected");
        };
        debug_assert!(!paths.is_global());

        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            )
            .into());
        }

        paths.ensure().await?;

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
            paths: Arc::new(paths.clone()),
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

    /// Create a new vault file on disc and the associated
    /// event log.
    ///
    /// If a vault file already exists it is overwritten if an
    /// event log exists it is truncated.
    ///
    /// Intended to be used by a server to create the identity
    /// vault and event log when a new account is created.
    pub async fn initialize_account(
        target: &BackendTarget,
        account_id: &AccountId,
        paths: &Paths,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let mut event_log =
            FolderEventLog::new_login_folder(target.clone(), account_id)
                .await?;
        event_log.clear().await?;
        event_log.patch_unchecked(identity_patch).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(paths.identity_vault(), buffer).await?;

        Ok(event_log)
    }
}

#[async_trait]
impl ServerAccountStorage for ServerFileStorage {
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
        let mut file = sos_filesystem::VaultFileWriter::<Error>::new(
            self.paths.identity_vault(),
        );
        file.set_vault_name(name.to_owned()).await?;
        Ok(())
    }

    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault> {
        let buffer = vfs::read(self.paths.vault_path(folder_id)).await?;
        Ok(decode(&buffer).await?)
    }

    async fn write_vault(&self, vault: &Vault) -> Result<()> {
        let buffer = encode(vault).await?;
        vfs::write(self.paths.vault_path(vault.id()), buffer).await?;
        Ok(())
    }

    /*
    async fn read_login_vault(&self) -> Result<Vault> {
        let buffer = vfs::read(self.paths.identity_vault()).await?;
        Ok(decode(&buffer).await?)
    }
    */

    async fn write_login_vault(&self, vault: &Vault) -> Result<()> {
        let buffer = encode(vault).await?;
        vfs::write(self.paths.identity_vault(), buffer).await?;
        Ok(())
    }

    async fn replace_folder(
        &self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<(FolderEventLog, Vault)> {
        let events_path = self.paths.event_log_path(folder_id);
        let mut event_log =
            FolderEventLog::new_fs_folder(events_path).await?;
        event_log.replace_all_events(&diff).await?;
        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
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
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log =
                FolderEventLog::new_fs_folder(events_path).await?;
            event_log.patch_unchecked(folder).await?;

            let vault = FolderReducer::new()
                .reduce(&event_log)
                .await?
                .build(false)
                .await?;

            let buffer = encode(&vault).await?;
            vfs::write(vault_path, buffer).await?;

            self.folders.insert(*id, Arc::new(RwLock::new(event_log)));
        }

        Ok(())
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
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

        for summary in &summaries {
            // Ensure we don't overwrite existing data
            if self.folders.get(summary.id()).is_none() {
                self.create_folder_entry(summary.id()).await?;
            }
        }
        Ok(summaries)
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
            event_log.apply(events.as_slice()).await?;
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

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        // Remove the files
        self.remove_vault_file(id).await?;

        // Remove local state
        self.folders.remove(id);

        #[cfg(feature = "files")]
        {
            let files_folder = self.paths.file_folder_location(id);
            if vfs::try_exists(&files_folder).await? {
                vfs::remove_dir_all(&files_folder).await?;
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

    async fn delete_account(&mut self) -> Result<()> {
        let user_dir = self.paths.user_dir();
        let identity_vault = self.paths.identity_vault();
        let identity_event = self.paths.identity_events();

        vfs::remove_dir_all(&user_dir).await?;

        // In some test specs we don't necessarily want to mock
        // this file
        if vfs::try_exists(&identity_vault).await? {
            vfs::remove_file(&identity_vault).await?;
        }
        vfs::remove_file(&identity_event).await?;
        Ok(())
    }
}

#[async_trait]
impl StorageEventLogs for ServerFileStorage {
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
        for id in &ids {
            let path = self.paths.vault_path(id);
            let summary = Header::read_summary_file(path).await?;
            output.insert(summary);
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
