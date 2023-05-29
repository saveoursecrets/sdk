use super::{Error, Result};
use async_trait::async_trait;
use sos_sdk::{
    commit::{event_log_commit_tree_file, CommitProof},
    constants::{EVENT_LOG_DELETED_EXT, EVENT_LOG_EXT, VAULT_EXT},
    decode, encode,
    events::WriteEvent,
    events::{EventLogFile, EventReducer},
    vault::{Header, Summary, Vault, VaultAccess, VaultWriter},
    vfs,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::FileLocks;

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

    /// Get a read reference to the event log implementation for the backend.
    pub async fn event_log_read(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&EventLogFile> {
        match self {
            Self::FileSystem(handler) => {
                handler.event_log_read(owner, vault_id).await
            }
        }
    }

    /// Get a write reference to the event log implementation for the backend.
    pub async fn event_log_write(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&mut EventLogFile> {
        match self {
            Self::FileSystem(handler) => {
                handler.event_log_write(owner, vault_id).await
            }
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
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(WriteEvent<'a>, CommitProof)>;

    // TODO: support account deletion

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &Address) -> bool;

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
        vault_id: &Uuid,
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
    ) -> Result<(WriteEvent<'a>, CommitProof)>;

    /* event log */

    /// Create a new event log.
    ///
    /// The owner directory must already exist.
    async fn create_event_log<'a>(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(WriteEvent<'a>, CommitProof)>;

    /// Delete a event log log and corresponding vault.
    async fn delete_event_log(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<()>;

    /// Determine if a vault exists and get it's commit proof
    /// if it already exists.
    async fn event_log_exists(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<(bool, Option<CommitProof>)>;

    /// Load a event log buffer for an account.
    async fn get_event_log(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>>;

    /// Replace a event log file with a new buffer.
    async fn replace_event_log(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        root_hash: [u8; 32],
        buffer: &[u8],
    ) -> Result<CommitProof>;
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    locks: FileLocks,
    startup_files: Vec<PathBuf>,
    accounts: HashMap<Address, HashMap<Uuid, EventLogFile>>,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new<P: AsRef<Path>>(directory: P) -> Self {
        let directory = directory.as_ref().to_path_buf();
        Self {
            directory,
            locks: Default::default(),
            startup_files: Vec::new(),
            accounts: Default::default(),
        }
    }

    /// Get a read reference to a event log file.
    pub async fn event_log_read(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&EventLogFile> {
        let account = self
            .accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let storage = account
            .get(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

        Ok(storage)
    }

    /// Get a write reference to a event log file.
    pub async fn event_log_write(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&mut EventLogFile> {
        let account = self
            .accounts
            .get_mut(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let storage = account
            .get_mut(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

        Ok(storage)
    }

    /// Read accounts and vault file paths into memory.
    pub async fn read_dir(&mut self) -> Result<()> {
        if !self.directory.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }
        let mut dir = vfs::read_dir(&self.directory).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<Address>()
                    {
                        let accounts = &mut self.accounts;
                        let _vaults = accounts
                            .entry(owner)
                            .or_insert(Default::default());

                        let mut dir = vfs::read_dir(&path).await?;
                        while let Some(entry) = dir.next_entry().await? {
                            let event_log_path = entry.path();
                            if let Some(ext) = event_log_path.extension() {
                                if ext == EVENT_LOG_EXT {
                                    let mut vault_path =
                                        event_log_path.to_path_buf();
                                    vault_path.set_extension(VAULT_EXT);
                                    if !vault_path.exists() {
                                        return Err(Error::NotFile(
                                            vault_path,
                                        ));
                                    }

                                    let summary = Header::read_summary_file(
                                        &vault_path,
                                    )?;
                                    let id = *summary.id();

                                    let mut event_log_file =
                                        EventLogFile::new(&event_log_path)
                                            .await?;
                                    event_log_file.load_tree()?;

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
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<(PathBuf, EventLogFile)> {
        let event_log_path = self.event_log_file_path(owner, vault_id);
        if event_log_path.exists() {
            return Err(Error::FileExists(event_log_path));
        }

        // Write out the vault for so that we can easily
        // list summaries
        let mut vault_path = event_log_path.clone();
        vault_path.set_extension(VAULT_EXT);
        vfs::write(&vault_path, vault).await?;

        // Create the event log file
        let mut event_log = EventLogFile::new(&event_log_path).await?;
        let event = WriteEvent::CreateVault(Cow::Borrowed(vault));
        event_log.append_event(event).await?;

        self.locks.add(&vault_path)?;
        self.locks.add(&event_log_path)?;

        Ok((event_log_path, event_log))
    }

    fn event_log_file_path(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> PathBuf {
        let account_dir = self.directory.join(owner.to_string());
        let mut event_log_file = account_dir.join(vault_id.to_string());
        event_log_file.set_extension(EVENT_LOG_EXT);
        event_log_file
    }

    fn vault_file_path(&self, owner: &Address, vault_id: &Uuid) -> PathBuf {
        let mut vault_path = self.event_log_file_path(owner, vault_id);
        vault_path.set_extension(VAULT_EXT);
        vault_path
    }

    /// Add a event log file path to the in-memory account.
    async fn add_event_log_path(
        &mut self,
        owner: Address,
        vault_id: Uuid,
        _event_log_path: PathBuf,
        event_log_file: EventLogFile,
    ) -> Result<()> {
        let vaults = self.accounts.entry(owner).or_insert(Default::default());
        vaults.insert(vault_id, event_log_file);
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
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(WriteEvent<'a>, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if account_dir.exists() {
            return Err(Error::DirectoryExists(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault)?;

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
        let event = WriteEvent::CreateVault(Cow::Borrowed(vault));
        Ok((event, proof))
    }

    async fn create_event_log<'a>(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(WriteEvent<'a>, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault)?;

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
        let event = WriteEvent::CreateVault(Cow::Borrowed(vault));
        Ok((event, proof))
    }

    async fn delete_event_log(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        let account = self
            .accounts
            .get_mut(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        account
            .get_mut(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;
        account.remove(vault_id).ok_or(Error::VaultRemove)?;

        let event_log_path = self.event_log_file_path(owner, vault_id);

        // Remove the vault file and lock
        let mut vault_path = event_log_path.clone();
        vault_path.set_extension(VAULT_EXT);
        let _ = tokio::fs::remove_file(&vault_path).await?;
        self.locks.remove(&vault_path)?;

        // Keep a backup of the event log file as .event_log.deleted
        let mut event_log_backup = event_log_path.clone();
        event_log_backup.set_extension(EVENT_LOG_DELETED_EXT);
        let _ = tokio::fs::rename(&event_log_path, event_log_backup).await?;
        self.locks.remove(&event_log_path)?;

        Ok(())
    }

    async fn account_exists(&self, owner: &Address) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        self.accounts.get(owner).is_some() && account_dir.is_dir()
    }

    async fn set_vault_name(
        &self,
        owner: &Address,
        vault_id: &Uuid,
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
        if let Some(account) = self.accounts.get(owner) {
            for id in account.keys() {
                let mut vault_path = self.event_log_file_path(owner, id);
                vault_path.set_extension(VAULT_EXT);
                let summary = Header::read_summary_file(&vault_path)?;
                summaries.push(summary);
            }
        }
        Ok(summaries)
    }

    async fn set_vault<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(WriteEvent<'a>, CommitProof)> {
        let _ = self
            .accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let vault: Vault = decode(vault)?;
        let (vault, events) = EventReducer::split(vault)?;

        // Prepare a temp file with the new event log records
        let temp = NamedTempFile::new()?;
        let mut temp_event_log = EventLogFile::new(temp.path()).await?;
        temp_event_log.apply(events, None).await?;

        let expected_root = temp_event_log
            .tree()
            .root()
            .ok_or_else(|| sos_sdk::Error::NoRootCommit)?;

        // Prepare the buffer for the vault file
        let vault_path = self.vault_file_path(owner, vault.id());
        // Re-encode with the new header-only vault
        let vault_buffer = encode(&vault)?;

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

        let event = WriteEvent::UpdateVault(Cow::Owned(vault_buffer));
        Ok((event, commit_proof))
    }

    async fn event_log_exists(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<(bool, Option<CommitProof>)> {
        if let Some(account) = self.accounts.get(owner) {
            if let Some(event_log) = account.get(vault_id) {
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
        vault_id: &Uuid,
    ) -> Result<Vec<u8>> {
        let account = self
            .accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let _ = account
            .get(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

        let event_log_file = self.event_log_file_path(owner, vault_id);
        let buffer = tokio::fs::read(event_log_file).await?;
        Ok(buffer)
    }

    async fn replace_event_log(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        root_hash: [u8; 32],
        mut buffer: &[u8],
    ) -> Result<CommitProof> {
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
        vfs::rename(&temp_path, &original_event_log).await?;

        let event_log = self.event_log_write(owner, vault_id).await?;
        *event_log = EventLogFile::new(&original_event_log).await?;
        event_log.load_tree()?;

        let new_tree_root = event_log
            .tree()
            .root()
            .ok_or(sos_sdk::Error::NoRootCommit)?;

        tracing::debug!(root = ?hex::encode(new_tree_root),
            "replace_event_log loaded a new tree root");

        if root_hash != new_tree_root {
            return Err(Error::EventValidateMismatch);
        }
        Ok(event_log.tree().head()?)
    }
}
