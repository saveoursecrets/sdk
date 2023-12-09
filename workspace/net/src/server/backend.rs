use super::{Error, Result};
use crate::{
    device::DeviceSet,
    sdk::{
        commit::CommitProof,
        constants::{DEVICES_FILE, EVENT_LOG_EXT, JSON_EXT, VAULT_EXT},
        decode,
        device::DevicePublicKey,
        encode,
        events::{
            AccountReducer, AuditEvent, Event, EventKind, EventReducer,
            FolderEventLog, WriteEvent,
        },
        signer::ecdsa::Address,
        storage::FolderStorage,
        vault::{Header, Summary, Vault, VaultAccess, VaultId, VaultWriter},
        vfs, Paths,
    },
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};

/// Account storage.
pub struct AccountStorage {
    pub(crate) folders: FolderStorage,
    /// Set of trusted devices.
    devices: DeviceSet,
}

impl AccountStorage {
    /// Trust a device.
    pub async fn trust_device(
        &mut self,
        public_key: DevicePublicKey,
    ) -> Result<()> {
        self.devices.0.insert(public_key);
        self.save_devices().await?;
        Ok(())
    }

    /// Revoke trust in a device.
    pub async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        self.devices.0.remove(public_key);
        self.save_devices().await?;
        Ok(())
    }

    /// Devices file for server-side storage.
    fn devices_file(&self) -> PathBuf {
        let mut path = self.folders.paths().user_dir().join(DEVICES_FILE);
        path.set_extension(JSON_EXT);
        path
    }

    async fn save_devices(&self) -> Result<()> {
        let path = self.devices_file();
        let contents = serde_json::to_vec(&self.devices)?;
        vfs::write(&path, contents).await?;
        Ok(())
    }

    async fn load_devices(&mut self) -> Result<()> {
        let path = self.devices_file();
        if vfs::try_exists(&path).await? {
            let contents = vfs::read(&path).await?;
            let devices: DeviceSet = serde_json::from_slice(&contents)?;
            self.devices = devices;
        }
        Ok(())
    }
}

/// Individual account.
pub type ServerAccount = Arc<RwLock<AccountStorage>>;

/// Collection of accounts by address.
pub type Accounts = Arc<RwLock<HashMap<Address, ServerAccount>>>;

/// Backend for a server.
pub enum Backend {
    /// File storage backend.
    FileSystem(FileSystemBackend),
}

impl Backend {
    /// Get a reference to the backend handler.
    pub fn handler(&self) -> &(impl BackendHandler + Send + Sync) {
        match self {
            Self::FileSystem(handler) => handler,
        }
    }

    /// Get a mutable reference to the backend handler.
    pub fn handler_mut(
        &mut self,
    ) -> &mut (impl BackendHandler + Send + Sync) {
        match self {
            Self::FileSystem(handler) => handler,
        }
    }

    /// Get the accounts map.
    pub fn accounts(&self) -> Accounts {
        match self {
            Self::FileSystem(handler) => handler.accounts(),
        }
    }
}

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait BackendHandler {
    /// Create a new account.
    async fn create_account(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
        device_public_key: DevicePublicKey,
    ) -> Result<(Event, CommitProof)>;

    // TODO: support account deletion

    /// Determine if an account exists.
    async fn account_exists(&self, owner: &Address) -> Result<bool>;

    /// Trust a device.
    async fn trust_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()>;

    /// Revoke trust in a device.
    async fn revoke_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()>;

    /// List folders for an account.
    async fn list_folders(&self, owner: &Address) -> Result<Vec<Summary>>;

    /// Import a folder overwriting any existing data.
    async fn import_folder<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(Event, CommitProof)>;

    /// Create a folder.
    async fn create_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
    ) -> Result<(Event, CommitProof)>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<()>;

    /// Determine if a folder exists.
    async fn folder_exists(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<(Option<Summary>, Option<CommitProof>)>;

    /// Load a event log buffer for an account.
    async fn read_events_buffer(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>>;
}

/// Backend storage for accounts on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    accounts: Accounts,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new<P: AsRef<Path>>(directory: P) -> Self {
        let directory = directory.as_ref().to_path_buf();
        Self {
            directory,
            accounts: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Get the accounts.
    pub fn accounts(&self) -> Accounts {
        Arc::clone(&self.accounts)
    }

    /// Read accounts and event logs into memory.
    pub async fn read_dir(&mut self) -> Result<()> {
        if !vfs::metadata(&self.directory).await?.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }

        let span = span!(Level::DEBUG, "server init");
        tracing::debug!(directory = %self.directory.display());

        Paths::scaffold(Some(self.directory.clone())).await?;
        let paths = Paths::new_global_server(self.directory.clone());

        if !vfs::try_exists(paths.local_dir()).await? {
            vfs::create_dir(paths.local_dir()).await?;
        }

        let mut dir = vfs::read_dir(paths.local_dir()).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if vfs::metadata(&path).await?.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<Address>()
                    {
                        tracing::debug!(account = %owner);
                        let mut account = AccountStorage {
                            folders: FolderStorage::new_server(
                                owner.clone(),
                                Some(self.directory.clone()),
                            )
                            .await?,
                            devices: Default::default(),
                        };
                        account.load_devices().await?;

                        let mut accounts = self.accounts.write().await;
                        let mut account = accounts
                            .entry(owner.clone())
                            .or_insert(Arc::new(RwLock::new(account)));
                        let mut writer = account.write().await;
                        writer.folders.load_vaults().await?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl BackendHandler for FileSystemBackend {
    async fn create_account(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
        device_public_key: DevicePublicKey,
    ) -> Result<(Event, CommitProof)> {
        {
            let accounts = self.accounts.read().await;
            let account = accounts.get(owner);

            if account.is_some() {
                return Err(Error::AccountExists(*owner));
            }
        }

        let span = span!(Level::DEBUG, "create_account");
        tracing::debug!(address = %owner);

        let paths =
            Paths::new_server(self.directory.clone(), owner.to_string());
        paths.ensure().await?;

        let mut account = AccountStorage {
            folders: FolderStorage::new_server(
                owner.clone(),
                Some(self.directory.clone()),
            )
            .await?,
            devices: Default::default(),
        };

        account.trust_device(device_public_key).await?;

        let mut accounts = self.accounts.write().await;
        let mut account = accounts
            .entry(owner.clone())
            .or_insert(Arc::new(RwLock::new(account)));
        let mut writer = account.write().await;

        let (event, summary) =
            writer.folders.import_folder(vault, None).await?;

        tracing::debug!(folder_id = %summary.id());

        let (_, proof) = writer.folders.commit_state(&summary).await?;

        Ok((event, proof))
    }

    async fn trust_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        writer.trust_device(device_public_key).await?;
        Ok(())
    }

    async fn revoke_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        writer.revoke_device(&device_public_key).await?;
        Ok(())
    }

    async fn create_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
    ) -> Result<(Event, CommitProof)> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        let folder = writer.folders.find(|s| s.id() == vault_id);

        if folder.is_some() {
            return Err(Error::FolderExists(owner.to_owned(), *vault_id));
        }

        // Check the supplied identifier matches the data in the vault
        let summary = Header::read_summary_slice(vault).await?;
        if summary.id() != vault_id {
            return Err(Error::BadRequest);
        }

        let (event, summary) =
            writer.folders.import_folder(vault, None).await?;
        let (_, proof) = writer.folders.commit_state(&summary).await?;

        Ok((event, proof))
    }

    async fn delete_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;
        let mut writer = account.write().await;
        let folder = writer
            .folders
            .find(|s| s.id() == vault_id)
            .cloned()
            .ok_or(Error::NoFolder(owner.to_owned(), *vault_id))?;
        writer.folders.delete_folder(&folder).await?;
        Ok(())
    }

    async fn account_exists(&self, owner: &Address) -> Result<bool> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(owner).is_some())
    }

    async fn list_folders(&self, owner: &Address) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let reader = account.read().await;
            summaries = reader.folders.folders().to_vec();

            let log =
                AuditEvent::new(EventKind::ListVaults, owner.clone(), None);
            reader
                .folders
                .paths()
                .append_audit_events(vec![log])
                .await?;
        }
        Ok(summaries)
    }

    async fn import_folder<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(Event, CommitProof)> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        let (event, summary) =
            writer.folders.import_folder(vault, None).await?;

        let (_, proof) = writer.folders.commit_state(&summary).await?;
        Ok((event, proof))
    }

    async fn folder_exists(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<(Option<Summary>, Option<CommitProof>)> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let account = account.read().await;
            let folder = account.folders.find(|s| s.id() == vault_id);
            if let Some(folder) = folder {
                let (_, proof) = account.folders.commit_state(folder).await?;
                Ok((Some(folder.clone()), Some(proof)))
            } else {
                Ok((None, None))
            }
        } else {
            Ok((None, None))
        }
    }

    async fn read_events_buffer(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;
        let reader = account.read().await;
        let folder = reader
            .folders
            .find(|s| s.id() == vault_id)
            .cloned()
            .ok_or(Error::NoFolder(owner.to_owned(), *vault_id))?;

        let paths = reader.folders.paths();
        let event_log = paths.event_log_path(vault_id);
        Ok(vfs::read(event_log).await?)
    }
}
