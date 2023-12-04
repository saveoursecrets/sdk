use super::{Error, Result};
use async_trait::async_trait;
use sos_sdk::{
    account::UserPaths,
    commit::{event_log_commit_tree_file, CommitProof},
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    decode, encode,
    events::WriteEvent,
    events::{EventReducer, FolderEventLog},
    storage::FolderStorage,
    vault::{Header, Summary, Vault, VaultAccess, VaultId, VaultWriter},
    vfs,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::NamedTempFile;
use tokio::sync::RwLock;
use tracing::{span, Level};
use web3_address::ethereum::Address;

use crate::FileLocks;

/// Server storage for an account.
pub struct AccountStorage {
    pub(crate) folders: FolderStorage,
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
    ) -> Result<(WriteEvent, CommitProof)>;

    // TODO: support account deletion

    /// Determine if an account exists.
    async fn account_exists(&self, owner: &Address) -> Result<bool>;

    /// List folders for an account.
    async fn list_folders(&self, owner: &Address) -> Result<Vec<Summary>>;

    /// Import a folder overwriting any existing data.
    async fn import_folder<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)>;

    /// Create a folder.
    async fn create_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
    ) -> Result<(WriteEvent, CommitProof)>;

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
    ) -> Result<(bool, Option<CommitProof>)>;

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

        UserPaths::scaffold(Some(self.directory.clone())).await?;
        let paths = UserPaths::new_global(self.directory.clone());

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
                        let account = AccountStorage {
                            folders: FolderStorage::new_server(
                                owner.to_string(),
                                Some(self.directory.clone()),
                            )
                            .await?,
                        };

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
    ) -> Result<(WriteEvent, CommitProof)> {
        {
            let accounts = self.accounts.read().await;
            let account = accounts.get(owner);

            if account.is_some() {
                return Err(Error::AccountExists(*owner));
            }
        }

        let span = span!(Level::DEBUG, "create_account");
        tracing::debug!(address = %owner);

        let paths = UserPaths::new(self.directory.clone(), owner.to_string());
        paths.ensure().await?;

        let account = AccountStorage {
            folders: FolderStorage::new_server(
                owner.to_string(),
                Some(self.directory.clone()),
            )
            .await?,
        };

        let mut accounts = self.accounts.write().await;
        let mut account = accounts
            .entry(owner.clone())
            .or_insert(Arc::new(RwLock::new(account)));
        let mut writer = account.write().await;

        let (event, summary) =
            writer.folders.import_vault(vault, None).await?;

        tracing::debug!(folder_id = %summary.id());

        let (_, proof) = writer.folders.commit_state(&summary).await?;

        let event = WriteEvent::CreateVault(vault.to_owned());
        Ok((event, proof))
    }

    async fn create_folder(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
    ) -> Result<(WriteEvent, CommitProof)> {
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
            writer.folders.import_vault(vault, None).await?;
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
        }
        Ok(summaries)
    }

    async fn import_folder<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        let (event, summary) =
            writer.folders.import_vault(vault, None).await?;

        let (_, proof) = writer.folders.commit_state(&summary).await?;
        Ok((event, proof))
    }

    async fn folder_exists(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<(bool, Option<CommitProof>)> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let account = account.read().await;
            let folder = account.folders.find(|s| s.id() == vault_id);
            if let Some(folder) = folder {
                let (_, proof) = account.folders.commit_state(folder).await?;
                Ok((true, Some(proof)))
            } else {
                Ok((false, None))
            }
        } else {
            Ok((false, None))
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
        let event_log = paths.event_log_path(vault_id.to_string());
        Ok(vfs::read(event_log).await?)
    }
}
