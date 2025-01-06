//! Server storage backed by the filesystem.
use crate::{Error, Result, ServerAccountStorage};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_core::{
    constants::VAULT_EXT,
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode, AccountId, Paths,
};
use sos_filesystem::{folder::FolderReducer, VaultWriter};
use sos_sdk::{
    events::{
        AccountEvent, AccountEventLog, DeviceEventLog, DeviceReducer,
        EventLogExt, FileEvent, FileEventLog, FolderEventLog, FolderPatch,
    },
    vault::{Header, Summary, Vault, VaultAccess, VaultId},
    vfs,
};
use sos_sync::{CreateSet, ForceMerge, MergeOutcome, UpdateSet};
use std::collections::HashSet;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "audit")]
use sos_audit::{append_audit_events, AuditEvent};

mod sync;

/// Server folders loaded into memory and mirrored to disc.
pub struct ServerFileStorage {
    /// Account identifier.
    pub(super) account_id: AccountId,

    /// Directories for file storage.
    pub(super) paths: Arc<Paths>,

    /// Identity folder event log.
    pub(super) identity_log: Arc<RwLock<FolderEventLog>>,

    /// Account event log.
    pub(super) account_log: Arc<RwLock<AccountEventLog>>,

    /// Folder event logs.
    pub(super) cache: HashMap<VaultId, Arc<RwLock<FolderEventLog>>>,

    /// Device event log.
    pub(super) device_log: Arc<RwLock<DeviceEventLog>>,

    /// Reduced collection of devices.
    pub(super) devices: IndexSet<TrustedDevice>,

    /// File event log.
    pub(super) file_log: Arc<RwLock<FileEventLog>>,
}

impl ServerFileStorage {
    /// Create folder storage for server-side access.
    pub async fn new(
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
        Self::new_paths(Arc::new(dirs), account_id, identity_log).await
    }

    /// Create new storage backed by files on disc.
    async fn new_paths(
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

        let log_file = paths.account_events();
        let mut event_log = AccountEventLog::new_account(log_file).await?;
        event_log.load_tree().await?;
        let account_log = Arc::new(RwLock::new(event_log));

        let (device_log, devices) =
            Self::initialize_device_log(&*paths).await?;

        let file_log = Self::initialize_file_log(&paths).await?;

        Ok(Self {
            account_id,
            cache: Default::default(),
            paths,
            identity_log,
            account_log,
            device_log: Arc::new(RwLock::new(device_log)),
            devices,
            file_log: Arc::new(RwLock::new(file_log)),
        })
    }

    async fn initialize_device_log(
        paths: &Paths,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)> {
        let log_file = paths.device_events();
        let mut event_log = DeviceEventLog::new_device(log_file).await?;
        event_log.load_tree().await?;

        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;

        Ok((event_log, devices))
    }

    async fn initialize_file_log(paths: &Paths) -> Result<FileEventLog> {
        use sos_database::files::list_external_files;

        let log_file = paths.file_events();
        let needs_init = !vfs::try_exists(&log_file).await?;
        let mut event_log = FileEventLog::new_file(log_file).await?;

        tracing::debug!(needs_init = %needs_init, "file_log");

        if needs_init {
            let files = list_external_files(paths).await?;
            let events: Vec<FileEvent> =
                files.into_iter().map(|f| f.into()).collect();

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(event_log)
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

    /// Create a new vault file on disc and the associated
    /// event log.
    ///
    /// If a vault file already exists it is overwritten if an
    /// event log exists it is truncated.
    ///
    /// Intended to be used by a server to create the identity
    /// vault and event log when a new account is created.
    pub async fn initialize_account(
        paths: &Paths,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let mut event_log =
            FolderEventLog::new(paths.identity_events()).await?;
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

    fn cache_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>> {
        &mut self.cache
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

        {
            let mut writer = self.file_log.write().await;
            writer.patch_unchecked(&account_data.files).await?;
        }

        for (id, folder) in &account_data.folders {
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log = FolderEventLog::new(events_path).await?;
            event_log.patch_unchecked(folder).await?;

            let vault = FolderReducer::new()
                .reduce(&event_log)
                .await?
                .build(false)
                .await?;

            let buffer = encode(&vault).await?;
            vfs::write(vault_path, buffer).await?;

            self.cache_mut()
                .insert(*id, Arc::new(RwLock::new(event_log)));
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

    async fn import_folder(
        &mut self,
        id: &VaultId,
        buffer: &[u8],
    ) -> Result<()> {
        let exists = self.cache.get(id).is_some();

        let vault: Vault = decode(buffer).await?;
        let (vault, events) = FolderReducer::split(vault).await?;

        if id != vault.id() {
            return Err(
                Error::VaultIdentifierMismatch(*id, *vault.id()).into()
            );
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
                (self.account_id(), &account_event).into();
            append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        // Remove the files
        self.remove_vault_file(id).await?;

        // Remove local state
        self.cache.remove(id);

        {
            let files_folder = self.paths.files_dir().join(id.to_string());
            if vfs::try_exists(&files_folder).await? {
                vfs::remove_dir_all(&files_folder).await?;
            }
        }

        #[cfg(feature = "audit")]
        {
            let account_event = AccountEvent::DeleteFolder(*id);
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    async fn rename_folder(
        &mut self,
        id: &VaultId,
        name: &str,
    ) -> Result<()> {
        // Update the vault on disc
        let vault_path = self.paths.vault_path(id);
        let mut access = VaultWriter::new(vault_path).await?;
        access.set_vault_name(name.to_owned()).await?;

        #[cfg(feature = "audit")]
        {
            let account_event =
                AccountEvent::RenameFolder(*id, name.to_owned());
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    async fn delete_account(&mut self) -> Result<()> {
        let user_dir = self.paths.user_dir();
        let identity_vault = self.paths.identity_vault();
        let identity_event = self.paths.identity_events();
        vfs::remove_dir_all(&user_dir).await?;
        vfs::remove_file(&identity_vault).await?;
        vfs::remove_file(&identity_event).await?;
        Ok(())
    }
}
