use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    commit_tree::{integrity::wal_commit_tree, CommitProof},
    events::{SyncEvent, WalEvent},
    file_access::VaultFileAccess,
    file_locks::FileLocks,
    vault::{Header, Summary, Vault, VaultAccess},
    wal::{
        file::{WalFile, WalFileRecord},
        WalProvider,
    },
};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use tempfile::NamedTempFile;
use uuid::Uuid;

use tokio::io;

type WalStorage = Box<
    dyn WalProvider<Item = WalFileRecord, Partial = Vec<u8>> + Send + Sync,
>;

const WAL_BACKUP_EXT: &str = "wal.backup";
const WAL_DELETED_EXT: &str = "wal.deleted";

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// Sets the lock files.
    fn set_file_locks(&mut self, locks: FileLocks) -> Result<()>;

    /// Get the lock files.
    fn file_locks(&self) -> &FileLocks;

    /// ACCOUNT ///

    /// Create a new account with the given default vault.
    ///
    /// The owner directory must not exist.
    async fn create_account<'a>(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(SyncEvent<'a>, CommitProof)>;

    // TODO: support account deletion

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &AddressStr) -> bool;

    /// VAULT ///

    /// List vaults for an account.
    ///
    /// Callers should ensure the account exists before attempting to
    /// list the vaults for an account.
    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>>;

    /// Set the name of the vault.
    async fn set_vault_name(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
        name: String,
    ) -> Result<()>;

    /// WAL ///

    /// Create a new WAL.
    ///
    /// The owner directory must already exist.
    async fn create_wal<'a>(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &'a [u8],
    ) -> Result<(SyncEvent<'a>, CommitProof)>;

    /// Delete a WAL log and corresponding vault.
    async fn delete_wal(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<()>;

    /// Determine if a vault exists and get it's change sequence
    /// if it already exists.
    async fn wal_exists(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<(bool, Option<CommitProof>)>;

    /// Get a read handle to an existing vault.
    async fn wal_read(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<&WalStorage>;

    /// Get a write handle to an existing vault.
    async fn wal_write(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<&mut WalStorage>;

    /// Load a WAL buffer for an account.
    async fn get_wal(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>>;

    /// Replace a WAL file with a new buffer.
    async fn replace_wal(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
        root_hash: [u8; 32],
        buffer: &[u8],
    ) -> Result<()>;
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    locks: FileLocks,
    startup_files: Vec<PathBuf>,
    accounts: HashMap<AddressStr, HashMap<Uuid, WalStorage>>,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            locks: Default::default(),
            startup_files: Vec::new(),
            accounts: Default::default(),
        }
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
                        name.to_string_lossy().parse::<AddressStr>()
                    {
                        let accounts = &mut self.accounts;
                        let _vaults = accounts
                            .entry(owner)
                            .or_insert(Default::default());
                        for entry in std::fs::read_dir(&path)? {
                            let entry = entry?;
                            let wal_path = entry.path();
                            if let Some(ext) = wal_path.extension() {
                                if ext == WalFile::extension() {
                                    let mut vault_path =
                                        wal_path.to_path_buf();
                                    vault_path
                                        .set_extension(Vault::extension());
                                    if !vault_path.exists() {
                                        return Err(Error::FileMissing(
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
        owner: &AddressStr,
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
        vault_path.set_extension(Vault::extension());
        tokio::fs::write(&vault_path, vault).await?;

        // Create the WAL file
        let mut wal = WalFile::new(&wal_path)?;
        let event = WalEvent::CreateVault(Cow::Borrowed(vault));
        wal.append_event(event)?;

        self.locks.add(&vault_path)?;
        self.locks.add(&wal_path)?;

        Ok((wal_path, wal))
    }

    fn wal_file_path(&self, owner: &AddressStr, vault_id: &Uuid) -> PathBuf {
        let account_dir = self.directory.join(owner.to_string());
        let mut wal_file = account_dir.join(vault_id.to_string());
        wal_file.set_extension(WalFile::extension());
        wal_file
    }

    /// Add a WAL file path to the in-memory account.
    async fn add_wal_path(
        &mut self,
        owner: AddressStr,
        vault_id: Uuid,
        _wal_path: PathBuf,
        wal_file: WalFile,
    ) -> Result<()> {
        let vaults = self.accounts.entry(owner).or_insert(Default::default());
        vaults.insert(vault_id, Box::new(wal_file));
        Ok(())
    }
}

#[async_trait]
impl Backend for FileSystemBackend {
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
        owner: &AddressStr,
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
        let event = SyncEvent::CreateVault(Cow::Borrowed(&vault));
        Ok((event, proof))
    }

    async fn create_wal<'a>(
        &mut self,
        owner: &AddressStr,
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
        let event = SyncEvent::CreateVault(Cow::Borrowed(&vault));
        Ok((event, proof))
    }

    async fn delete_wal(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        if let Some(account) = self.accounts.get_mut(owner) {
            if let Some(_) = account.get_mut(vault_id) {
                let removed = account.remove(vault_id);
                if let Some(_) = removed {
                    let wal_path = self.wal_file_path(owner, vault_id);

                    // Remove the vault file and lock
                    let mut vault_path = wal_path.clone();
                    vault_path.set_extension(Vault::extension());
                    let _ = tokio::fs::remove_file(&vault_path).await?;
                    self.locks.remove(&vault_path)?;

                    // Keep a backup of the WAL file as .wal.deleted
                    let mut wal_backup = wal_path.clone();
                    wal_backup.set_extension(WAL_DELETED_EXT);
                    let _ = tokio::fs::rename(&wal_path, wal_backup).await?;
                    self.locks.remove(&wal_path)?;

                    Ok(())
                } else {
                    Err(Error::VaultRemove)
                }
            } else {
                Err(Error::VaultNotExist(*vault_id))
            }
        } else {
            Err(Error::AccountNotExist(*owner))
        }
    }

    async fn account_exists(&self, owner: &AddressStr) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        self.accounts.get(owner).is_some() && account_dir.is_dir()
    }

    async fn set_vault_name(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
        name: String,
    ) -> Result<()> {
        let mut vault_path = self.wal_file_path(owner, vault_id);
        vault_path.set_extension(Vault::extension());
        let mut access = VaultFileAccess::new(&vault_path)?;
        let _ = access.set_vault_name(name)?;
        Ok(())
    }

    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        if let Some(account) = self.accounts.get(owner) {
            for (id, _) in account {
                let mut vault_path = self.wal_file_path(owner, id);
                vault_path.set_extension(Vault::extension());
                let summary = Header::read_summary_file(&vault_path)?;
                summaries.push(summary);
            }
        }
        Ok(summaries)
    }

    async fn wal_exists(
        &self,
        owner: &AddressStr,
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
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>> {
        if let Some(account) = self.accounts.get(owner) {
            if let Some(_) = account.get(vault_id) {
                let wal_file = self.wal_file_path(owner, vault_id);
                let buffer = tokio::fs::read(wal_file).await?;
                Ok(buffer)
            } else {
                Err(Error::VaultNotExist(*vault_id))
            }
        } else {
            Err(Error::AccountNotExist(*owner))
        }
    }

    async fn wal_read(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<&WalStorage> {
        if let Some(account) = self.accounts.get(owner) {
            if let Some(storage) = account.get(vault_id) {
                Ok(storage)
            } else {
                Err(Error::VaultNotExist(*vault_id))
            }
        } else {
            Err(Error::AccountNotExist(*owner))
        }
    }

    async fn wal_write(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<&mut WalStorage> {
        if let Some(account) = self.accounts.get_mut(owner) {
            if let Some(storage) = account.get_mut(vault_id) {
                Ok(storage)
            } else {
                Err(Error::VaultNotExist(*vault_id))
            }
        } else {
            Err(Error::AccountNotExist(*owner))
        }
    }

    async fn replace_wal(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
        root_hash: [u8; 32],
        mut buffer: &[u8],
    ) -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let temp_path = tempfile.path().to_path_buf();
        let mut tempfile = tokio::fs::File::from_std(tempfile.into_file());

        io::copy(&mut buffer, &mut tempfile).await?;

        // Compute the root hash of the submitted WAL file
        // and verify the integrity of each record event against
        // each leaf node hash
        let tree = wal_commit_tree(&temp_path, true, |_| {})?;
        let tree_root = tree.root().ok_or(sos_core::Error::NoRootCommit)?;

        // If the hash does not match the header then
        // something went wrong with the client POST
        // or was modified in transit
        if root_hash != tree_root {
            return Err(Error::WalValidateMismatch);
        }

        let original_wal = self.wal_file_path(owner, vault_id);

        let mut backup_wal = original_wal.clone();
        backup_wal.set_extension(WAL_BACKUP_EXT);

        std::fs::rename(&original_wal, &backup_wal)?;
        std::fs::rename(&temp_path, &original_wal)?;

        Ok(())
    }
}
