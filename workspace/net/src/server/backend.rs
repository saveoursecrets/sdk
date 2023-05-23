use super::{Error, Result};
use async_trait::async_trait;
use sos_sdk::{
    commit::{wal_commit_tree_file, CommitProof},
    constants::{VAULT_EXT, WAL_DELETED_EXT, WAL_EXT},
    decode, encode,
    events::SyncEvent,
    vault::{Header, Summary, Vault, VaultAccess, VaultFileAccess},
    vfs,
    wal::{WalFile, WalReducer},
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

    /// Get a read reference to the WAL implementation for the backend.
    pub async fn wal_read(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&WalFile> {
        match self {
            Self::FileSystem(handler) => {
                handler.wal_read(owner, vault_id).await
            }
        }
    }

    /// Get a write reference to the WAL implementation for the backend.
    pub async fn wal_write(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&mut WalFile> {
        match self {
            Self::FileSystem(handler) => {
                handler.wal_write(owner, vault_id).await
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
    ) -> Result<(SyncEvent<'a>, CommitProof)>;

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

    /// Overwrite the vault and WAL file from a buffer
    /// containing a new vault.
    ///
    /// This is used when a vault password has been changed.
    async fn set_vault<'a>(
        &mut self,
        owner: &Address,
        vault: &'a [u8],
    ) -> Result<(SyncEvent<'a>, CommitProof)>;

    /* WAL */

    /// Create a new WAL.
    ///
    /// The owner directory must already exist.
    async fn create_wal<'a>(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(SyncEvent<'a>, CommitProof)>;

    /// Delete a WAL log and corresponding vault.
    async fn delete_wal(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<()>;

    /// Determine if a vault exists and get it's commit proof
    /// if it already exists.
    async fn wal_exists(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<(bool, Option<CommitProof>)>;

    /// Load a WAL buffer for an account.
    async fn get_wal(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>>;

    /// Replace a WAL file with a new buffer.
    async fn replace_wal(
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
    accounts: HashMap<Address, HashMap<Uuid, WalFile>>,
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

    /// Get a read reference to a WAL file.
    pub async fn wal_read(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&WalFile> {
        let account = self
            .accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let storage = account
            .get(vault_id)
            .ok_or_else(|| Error::VaultNotExist(*vault_id))?;

        Ok(storage)
    }

    /// Get a write reference to a WAL file.
    pub async fn wal_write(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<&mut WalFile> {
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

        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
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
                        for entry in std::fs::read_dir(&path)? {
                            let entry = entry?;
                            let wal_path = entry.path();
                            if let Some(ext) = wal_path.extension() {
                                if ext == WAL_EXT {
                                    let mut vault_path =
                                        wal_path.to_path_buf();
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

                                    let mut wal_file =
                                        WalFile::new(&wal_path)?;
                                    wal_file.load_tree()?;

                                    // Store these file paths so locks
                                    // are acquired later
                                    self.startup_files
                                        .push(vault_path.to_path_buf());
                                    self.startup_files
                                        .push(wal_path.to_path_buf());

                                    self.add_wal_path(
                                        owner, id, wal_path, wal_file,
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

    /// Write a WAL file to disc for the given owner address.
    async fn new_wal_file(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<(PathBuf, WalFile)> {
        let wal_path = self.wal_file_path(owner, vault_id);
        if wal_path.exists() {
            return Err(Error::FileExists(wal_path));
        }

        // Write out the vault for so that we can easily
        // list summaries
        let mut vault_path = wal_path.clone();
        vault_path.set_extension(VAULT_EXT);
        tokio::fs::write(&vault_path, vault).await?;

        // Create the WAL file
        let mut wal = WalFile::new(&wal_path)?;
        let event = SyncEvent::CreateVault(Cow::Borrowed(vault));
        wal.append_event(event)?;

        self.locks.add(&vault_path)?;
        self.locks.add(&wal_path)?;

        Ok((wal_path, wal))
    }

    fn wal_file_path(&self, owner: &Address, vault_id: &Uuid) -> PathBuf {
        let account_dir = self.directory.join(owner.to_string());
        let mut wal_file = account_dir.join(vault_id.to_string());
        wal_file.set_extension(WAL_EXT);
        wal_file
    }

    fn vault_file_path(&self, owner: &Address, vault_id: &Uuid) -> PathBuf {
        let mut vault_path = self.wal_file_path(owner, vault_id);
        vault_path.set_extension(VAULT_EXT);
        vault_path
    }

    /// Add a WAL file path to the in-memory account.
    async fn add_wal_path(
        &mut self,
        owner: Address,
        vault_id: Uuid,
        _wal_path: PathBuf,
        wal_file: WalFile,
    ) -> Result<()> {
        let vaults = self.accounts.entry(owner).or_insert(Default::default());
        vaults.insert(vault_id, wal_file);
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
    ) -> Result<(SyncEvent<'a>, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if account_dir.exists() {
            return Err(Error::DirectoryExists(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault)?;

        tokio::fs::create_dir(account_dir).await?;
        let (wal_path, wal_file) =
            self.new_wal_file(owner, vault_id, vault).await?;
        let proof = wal_file.tree().head()?;
        self.add_wal_path(*owner, *summary.id(), wal_path, wal_file)
            .await?;
        let event = SyncEvent::CreateVault(Cow::Borrowed(vault));
        Ok((event, proof))
    }

    async fn create_wal<'a>(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(SyncEvent<'a>, CommitProof)> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        // Check it looks like a vault payload
        let summary = Header::read_summary_slice(vault)?;

        let (wal_path, wal_file) =
            self.new_wal_file(owner, vault_id, vault).await?;

        let proof = wal_file.tree().head()?;
        self.add_wal_path(*owner, *summary.id(), wal_path, wal_file)
            .await?;
        let event = SyncEvent::CreateVault(Cow::Borrowed(vault));
        Ok((event, proof))
    }

    async fn delete_wal(
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

        let wal_path = self.wal_file_path(owner, vault_id);

        // Remove the vault file and lock
        let mut vault_path = wal_path.clone();
        vault_path.set_extension(VAULT_EXT);
        let _ = tokio::fs::remove_file(&vault_path).await?;
        self.locks.remove(&vault_path)?;

        // Keep a backup of the WAL file as .wal.deleted
        let mut wal_backup = wal_path.clone();
        wal_backup.set_extension(WAL_DELETED_EXT);
        let _ = tokio::fs::rename(&wal_path, wal_backup).await?;
        self.locks.remove(&wal_path)?;

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
        let vault_file = VaultFileAccess::open(&vault_path)?;
        let mut access = VaultFileAccess::new(vault_path, vault_file)?;
        let _ = access.set_vault_name(name)?;
        Ok(())
    }

    async fn list(&self, owner: &Address) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        if let Some(account) = self.accounts.get(owner) {
            for id in account.keys() {
                let mut vault_path = self.wal_file_path(owner, id);
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
    ) -> Result<(SyncEvent<'a>, CommitProof)> {
        let _ = self
            .accounts
            .get(owner)
            .ok_or_else(|| Error::AccountNotExist(*owner))?;

        let vault: Vault = decode(vault)?;
        let (vault, events) = WalReducer::split(vault)?;

        // Prepare a temp file with the new WAL records
        let temp = NamedTempFile::new()?;
        let mut temp_wal = WalFile::new(temp.path())?;
        temp_wal.apply(events, None)?;

        let expected_root = temp_wal
            .tree()
            .root()
            .ok_or_else(|| sos_sdk::Error::NoRootCommit)?;

        // Prepare the buffer for the vault file
        let vault_path = self.vault_file_path(owner, vault.id());
        // Re-encode with the new header-only vault
        let vault_buffer = encode(&vault)?;

        // Read in the buffer of the WAL data so we can replace
        // the existing WAL using the standard logic
        let wal_buffer = tokio::fs::read(temp.path()).await?;

        // FIXME: make this transactional so we revert to the
        // FIXME: last WAL and vault file(s) on failure

        // Replace the WAL with the new buffer
        let commit_proof = self
            .replace_wal(owner, vault.id(), expected_root, &wal_buffer)
            .await?;

        // Write out the vault file (header only)
        tokio::fs::write(&vault_path, &vault_buffer).await?;

        let event = SyncEvent::UpdateVault(Cow::Owned(vault_buffer));
        Ok((event, commit_proof))
    }

    async fn wal_exists(
        &self,
        owner: &Address,
        vault_id: &Uuid,
    ) -> Result<(bool, Option<CommitProof>)> {
        if let Some(account) = self.accounts.get(owner) {
            if let Some(wal) = account.get(vault_id) {
                Ok((true, Some(wal.tree().head()?)))
            } else {
                Ok((false, None))
            }
        } else {
            Ok((false, None))
        }
    }

    async fn get_wal(
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

        let wal_file = self.wal_file_path(owner, vault_id);
        let buffer = tokio::fs::read(wal_file).await?;
        Ok(buffer)
    }

    async fn replace_wal(
        &mut self,
        owner: &Address,
        vault_id: &Uuid,
        root_hash: [u8; 32],
        mut buffer: &[u8],
    ) -> Result<CommitProof> {
        let mut tempfile = NamedTempFile::new()?;
        let temp_path = tempfile.path().to_path_buf();

        tracing::debug!(len = ?buffer.len(),
            "replace_wal got buffer length");

        tracing::debug!(expected_root = ?hex::encode(root_hash),
            "replace_wal expects root hash");

        // NOTE: using tokio::io here would hang sometimes
        std::io::copy(&mut buffer, &mut tempfile)?;

        tracing::debug!("replace_wal copied to temp file");

        // Compute the root hash of the submitted WAL file
        // and verify the integrity of each record event against
        // each leaf node hash
        let tree = wal_commit_tree_file(&temp_path, true, |_| {}).await?;

        let tree_root = tree.root().ok_or(sos_sdk::Error::NoRootCommit)?;

        tracing::debug!(root = ?hex::encode(tree_root),
            "replace_wal computed a new tree root");

        // If the hash does not match the header then
        // something went wrong with the client POST
        // or was modified in transit
        if root_hash != tree_root {
            return Err(Error::WalValidateMismatch);
        }

        let original_wal = self.wal_file_path(owner, vault_id);

        // Remove the existing WAL
        vfs::remove_file(&original_wal).await?;

        // Move the temp file with the new contents into place
        vfs::rename(&temp_path, &original_wal).await?;

        let wal = self.wal_write(owner, vault_id).await?;
        *wal = WalFile::new(&original_wal)?;
        wal.load_tree()?;

        let new_tree_root =
            wal.tree().root().ok_or(sos_sdk::Error::NoRootCommit)?;

        tracing::debug!(root = ?hex::encode(new_tree_root),
            "replace_wal loaded a new tree root");

        if root_hash != new_tree_root {
            return Err(Error::WalValidateMismatch);
        }
        Ok(wal.tree().head()?)
    }
}
