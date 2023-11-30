use super::{Error, Result};
use async_trait::async_trait;
use sos_sdk::{
    commit::{event_log_commit_tree_file, CommitProof},
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    decode, encode,
    events::WriteEvent,
    events::{EventReducer, FolderEventLog},
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
use web3_address::ethereum::Address;

use crate::FileLocks;

/// Individual account maps vault identifiers to the event logs.
pub type VaultMap = Arc<RwLock<HashMap<VaultId, FolderEventLog>>>;

/// Collection of accounts by address.
pub type AccountsMap = Arc<RwLock<HashMap<Address, VaultMap>>>;

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
    pub fn accounts(&self) -> AccountsMap {
        match self {
            Self::FileSystem(handler) => handler.accounts(),
        }
    }
}

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait BackendHandler {
    /// Sets the lock files.
    fn set_file_locks(&mut self, locks: FileLocks) -> Result<()>;

    /// Get the lock files.
    fn file_locks(&self) -> &FileLocks;

    /* ACCOUNT */

    /// Create a new account with the given default vault.
    ///
    /// The owner directory must not exist.
    async fn create_account<'a>(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)>;

    // TODO: support account deletion

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &Address) -> Result<bool>;

    /* VAULT */

    /// List vaults for an account.
    ///
    /// Callers should ensure the account exists before attempting to
    /// list the vaults for an account.
    async fn list(&self, owner: &Address) -> Result<Vec<Summary>>;

    /// Set the name of the vault.
    async fn set_vault_name(
        &self,
        owner: &Address,
        vault_id: &VaultId,
        name: String,
    ) -> Result<()>;

    /// Overwrite the vault and event log file from a buffer
    /// containing a new vault.
    ///
    /// This is used when a vault password has been changed.
    async fn set_vault<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)>;

    /* event log */

    /// Create a new event log.
    ///
    /// The owner directory must already exist.
    async fn create_event_log<'a>(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)>;

    /// Delete a event log log and corresponding vault.
    async fn delete_event_log(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<()>;

    /// Determine if a vault exists and get it's commit proof
    /// if it already exists.
    async fn event_log_exists(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<(bool, Option<CommitProof>)>;

    /// Load a event log buffer for an account.
    async fn get_event_log(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>>;

    /// Replace a event log file with a new buffer.
    async fn replace_event_log(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        root_hash: [u8; 32],
        buffer: &[u8],
    ) -> Result<CommitProof>;
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    locks: FileLocks,
    startup_files: Vec<PathBuf>,
    accounts: AccountsMap,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new<P: AsRef<Path>>(directory: P) -> Self {
        let directory = directory.as_ref().to_path_buf();
        Self {
            directory,
            locks: Default::default(),
            startup_files: Vec::new(),
            accounts: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Get the accounts map.
    pub fn accounts(&self) -> AccountsMap {
        Arc::clone(&self.accounts)
    }

    /// Read accounts and vault file paths into memory.
    pub async fn read_dir(&mut self) -> Result<()> {
        if !vfs::metadata(&self.directory).await?.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }
        let mut dir = vfs::read_dir(&self.directory).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if vfs::metadata(&path).await?.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<Address>()
                    {
                        {
                            let mut accounts = self.accounts.write().await;
                            accounts.insert(owner, Default::default());
                        }

                        let mut dir = vfs::read_dir(&path).await?;
                        while let Some(entry) = dir.next_entry().await? {
                            let event_log_path = entry.path();
                            if let Some(ext) = event_log_path.extension() {
                                if ext == EVENT_LOG_EXT {
                                    let mut vault_path =
                                        event_log_path.to_path_buf();
                                    vault_path.set_extension(VAULT_EXT);
                                    if !vfs::try_exists(&vault_path).await? {
                                        return Err(Error::NotFile(
                                            vault_path,
                                        ));
                                    }

                                    let summary = Header::read_summary_file(
                                        &vault_path,
                                    )
                                    .await?;
                                    let id = *summary.id();

                                    let mut event_log_file =
                                        FolderEventLog::new_folder(
                                            &event_log_path,
                                        )
                                        .await?;
                                    event_log_file.load_tree().await?;

                                    // Store these file paths so locks
                                    // are acquired later
                                    self.startup_files
                                        .push(vault_path.to_path_buf());
                                    self.startup_files
                                        .push(event_log_path.to_path_buf());

                                    self.add_event_log_path(
                                        owner,
                                        id,
                                        event_log_path,
                                        event_log_file,
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Write a event log file to disc for the given owner address.
    async fn new_event_log_file(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &[u8],
    ) -> Result<(PathBuf, FolderEventLog)> {
        let event_log_path = self.event_log_file_path(owner, vault_id);
        if vfs::try_exists(&event_log_path).await? {
            return Err(Error::FileExists(event_log_path));
        }

        // Write out the vault for so that we can easily
        // list summaries
        let mut vault_path = event_log_path.clone();
        vault_path.set_extension(VAULT_EXT);
        vfs::write(&vault_path, vault).await?;

        // Create the event log file
        let mut event_log =
            FolderEventLog::new_folder(&event_log_path).await?;
        let event = WriteEvent::CreateVault(vault.to_vec());
        event_log.append_event(&event).await?;

        self.locks.add(&vault_path)?;
        self.locks.add(&event_log_path)?;

        Ok((event_log_path, event_log))
    }

    fn event_log_file_path(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> PathBuf {
        let account_dir = self.directory.join(owner.to_string());
        let mut event_log_file = account_dir.join(vault_id.to_string());
        event_log_file.set_extension(EVENT_LOG_EXT);
        event_log_file
    }

    fn vault_file_path(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> PathBuf {
        let mut vault_path = self.event_log_file_path(owner, vault_id);
        vault_path.set_extension(VAULT_EXT);
        vault_path
    }

    /// Add a event log file path to the in-memory account.
    async fn add_event_log_path(
        &mut self,
        owner: Address,
        vault_id: VaultId,
        _event_log_path: PathBuf,
        event_log_file: FolderEventLog,
    ) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        let vaults = accounts
            .entry(owner)
            .or_insert(Arc::new(RwLock::new(Default::default())));
        let mut writer = vaults.write().await;
        writer.insert(vault_id, event_log_file);
        Ok(())
    }
}

#[async_trait]
impl BackendHandler for FileSystemBackend {
    fn set_file_locks(&mut self, mut locks: FileLocks) -> Result<()> {
        for file in &self.startup_files {
            locks.add(file)?;
        }
        self.locks = locks;
        self.startup_files.clear();
        Ok(())
    }

    fn file_locks(&self) -> &FileLocks {
        &self.locks
    }

    async fn create_account<'a>(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if vfs::try_exists(&account_dir).await? {
            return Err(Error::DirectoryExists(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault).await?;

        tokio::fs::create_dir(account_dir).await?;
        let (event_log_path, event_log_file) =
            self.new_event_log_file(owner, vault_id, vault).await?;
        let proof = event_log_file.tree().head()?;

        self.add_event_log_path(
            *owner,
            *summary.id(),
            event_log_path,
            event_log_file,
        )
        .await?;

        let event = WriteEvent::CreateVault(vault.to_owned());
        Ok((event, proof))
    }

    async fn create_event_log<'a>(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if !vfs::metadata(&account_dir).await?.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault).await?;

        let (event_log_path, event_log_file) =
            self.new_event_log_file(owner, vault_id, vault).await?;

        let proof = event_log_file.tree().head()?;
        self.add_event_log_path(
            *owner,
            *summary.id(),
            event_log_path,
            event_log_file,
        )
        .await?;
        let event = WriteEvent::CreateVault(vault.to_owned());
        Ok((event, proof))
    }

    async fn delete_event_log(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !vfs::metadata(&account_dir).await?.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        let mut accounts = self.accounts.write().await;
        let account = accounts
            .get_mut(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let mut vaults = account.write().await;
        vaults
            .get_mut(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;
        vaults.remove(vault_id).ok_or(Error::VaultRemove)?;

        let event_log_path = self.event_log_file_path(owner, vault_id);

        // Remove the vault file and lock
        let mut vault_path = event_log_path.clone();
        vault_path.set_extension(VAULT_EXT);
        let _ = tokio::fs::remove_file(&vault_path).await?;
        self.locks.remove(&vault_path)?;

        // Remove the event log file and lock
        let _ = tokio::fs::remove_file(&event_log_path).await?;
        self.locks.remove(&event_log_path)?;

        Ok(())
    }

    async fn account_exists(&self, owner: &Address) -> Result<bool> {
        let account_dir = self.directory.join(owner.to_string());
        let accounts = self.accounts.read().await;
        Ok(accounts.get(owner).is_some()
            && vfs::metadata(&account_dir).await?.is_dir())
    }

    async fn set_vault_name(
        &self,
        owner: &Address,
        vault_id: &VaultId,
        name: String,
    ) -> Result<()> {
        let vault_path = self.vault_file_path(owner, vault_id);
        let vault_file = VaultWriter::open(&vault_path).await?;
        let mut access = VaultWriter::new(vault_path, vault_file)?;
        let _ = access.set_vault_name(name).await?;
        Ok(())
    }

    async fn list(&self, owner: &Address) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let reader = account.read().await;
            for id in reader.keys() {
                let mut vault_path = self.event_log_file_path(owner, id);
                vault_path.set_extension(VAULT_EXT);
                let summary = Header::read_summary_file(&vault_path).await?;
                summaries.push(summary);
            }
        }
        Ok(summaries)
    }

    async fn set_vault<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(WriteEvent, CommitProof)> {
        {
            let accounts = self.accounts.read().await;
            accounts
                .get(owner)
                .ok_or_else(|| Error::AccountNotExist(*owner))?;
        }

        let vault: Vault = decode(vault).await?;
        let (vault, events) = EventReducer::split(vault).await?;

        // Prepare a temp file with the new event log records
        let temp = NamedTempFile::new()?;
        let mut temp_event_log =
            FolderEventLog::new_folder(temp.path()).await?;
        temp_event_log.apply(events.iter().collect()).await?;

        let expected_root = temp_event_log
            .tree()
            .root()
            .ok_or_else(|| sos_sdk::Error::NoRootCommit)?;

        // Prepare the buffer for the vault file
        let vault_path = self.vault_file_path(owner, vault.id());
        // Re-encode with the new header-only vault
        let vault_buffer = encode(&vault).await?;

        // Read in the buffer of the event log data so we can replace
        // the existing event log using the standard logic
        let event_log_buffer = tokio::fs::read(temp.path()).await?;

        // FIXME: make this transactional so we revert to the
        // FIXME: last event log and vault file(s) on failure

        // Replace the event log with the new buffer
        let commit_proof = self
            .replace_event_log(
                owner,
                vault.id(),
                expected_root,
                &event_log_buffer,
            )
            .await?;

        // Write out the vault file (header only)
        tokio::fs::write(&vault_path, &vault_buffer).await?;

        let event = WriteEvent::UpdateVault(vault_buffer);
        Ok((event, commit_proof))
    }

    async fn event_log_exists(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<(bool, Option<CommitProof>)> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let vaults = account.read().await;
            if let Some(event_log) = vaults.get(vault_id) {
                Ok((true, Some(event_log.tree().head()?)))
            } else {
                Ok((false, None))
            }
        } else {
            Ok((false, None))
        }
    }

    async fn get_event_log(
        &self,
        owner: &Address,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let vaults = account.read().await;
        vaults
            .get(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

        let event_log_file = self.event_log_file_path(owner, vault_id);
        let buffer = tokio::fs::read(event_log_file).await?;
        Ok(buffer)
    }

    async fn replace_event_log(
        &mut self,
        owner: &Address,
        vault_id: &VaultId,
        root_hash: [u8; 32],
        mut buffer: &[u8],
    ) -> Result<CommitProof> {
        {
            let accounts = self.accounts.read().await;
            accounts
                .get(owner)
                .ok_or_else(|| Error::AccountNotExist(*owner))?;
        }

        let mut tempfile = NamedTempFile::new()?;
        let temp_path = tempfile.path().to_path_buf();

        tracing::debug!(len = ?buffer.len(),
            "replace_event_log got buffer length");

        tracing::debug!(expected_root = ?hex::encode(root_hash),
            "replace_event_log expects root hash");

        // NOTE: using tokio::io here would hang sometimes
        std::io::copy(&mut buffer, &mut tempfile)?;

        tracing::debug!("replace_event_log copied to temp file");

        // Compute the root hash of the submitted event log file
        // and verify the integrity of each record event against
        // each leaf node hash
        let tree =
            event_log_commit_tree_file(&temp_path, true, |_| {}).await?;

        let tree_root = tree.root().ok_or(sos_sdk::Error::NoRootCommit)?;

        tracing::debug!(root = ?hex::encode(tree_root),
            "replace_event_log computed a new tree root");

        // If the hash does not match the header then
        // something went wrong with the client POST
        // or was modified in transit
        if root_hash != tree_root {
            return Err(Error::EventValidateMismatch);
        }

        let original_event_log = self.event_log_file_path(owner, vault_id);

        // Remove the existing event log
        vfs::remove_file(&original_event_log).await?;

        // Move the temp file with the new contents into place
        //
        // NOTE: we would prefer to rename but on linux we
        // NOTE: can hit ErrorKind::CrossesDevices
        //
        // But it's a nightly only variant so can't use it yet to
        // determine whether to rename or copy.
        vfs::copy(&temp_path, &original_event_log).await?;

        let (new_tree_root, head) = {
            let mut writer = self.accounts.write().await;

            let account = writer
                .get_mut(owner)
                .ok_or_else(|| Error::AccountNotExist(*owner))?;

            let mut vaults = account.write().await;
            let event_log = vaults
                .get_mut(vault_id)
                .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

            *event_log =
                FolderEventLog::new_folder(&original_event_log).await?;
            event_log.load_tree().await?;
            let root = event_log
                .tree()
                .root()
                .ok_or(sos_sdk::Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            (root, head)
        };

        tracing::debug!(root = ?hex::encode(new_tree_root),
            "replace_event_log loaded a new tree root");

        if root_hash != new_tree_root {
            return Err(Error::EventValidateMismatch);
        }
        Ok(head)
    }
}
