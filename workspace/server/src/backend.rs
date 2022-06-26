use crate::{file_locks::FileLocks, Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    events::WalEvent,
    file_access::VaultFileAccess,
    vault::{Header, Summary, Vault, VaultAccess},
    wal::{
        file::{WalFile, WalFileRow},
        WalItem, WalProvider,
    },
};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use tokio::sync::{
    RwLock, RwLockMappedWriteGuard, RwLockReadGuard, RwLockWriteGuard,
};
use uuid::Uuid;

type VaultStorage = Box<dyn VaultAccess + Send + Sync>;
type WalStorage<T> = Box<dyn WalProvider<Item = T> + Send + Sync>;

const WAL_EXT: &str = "wal";
const WAL_DELETED_EXT: &str = "wal.deleted";

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// Sets the lock files.
    fn set_file_locks(&mut self, locks: FileLocks) -> Result<()>;

    /// Get the lock files.
    fn file_locks(&self) -> &FileLocks;

    /// Create a new account with the given default vault.
    ///
    /// The owner directory must not exist.
    async fn create_account(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Create a new vault.
    ///
    /// The owner directory must already exist.
    async fn create_vault(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Delete a vault.
    async fn delete_vault(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<()>;

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &AddressStr) -> bool;

    /// List vaults for an account.
    ///
    /// Callers should ensure the account exists before attempting to
    /// list the the vaults for an account.
    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>>;

    /// Determine if a vault exists and get it's change sequence
    /// if it already exists.
    async fn vault_exists(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<(bool, u32)>;

    /// Load a vault buffer for an account.
    async fn get(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>>;

    /// Get a read handle to an existing vault.
    async fn vault_read<'a>(
        &'a self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<RwLockReadGuard<'a, VaultStorage>>;

    /// Get a write handle to an existing vault.
    async fn vault_write<'a>(
        &'a mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<RwLockMappedWriteGuard<'a, VaultStorage>>;
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    locks: FileLocks,
    files: Vec<PathBuf>,
    accounts: RwLock<
        HashMap<
            AddressStr,
            HashMap<Uuid, (VaultStorage, WalStorage<WalFileRow>)>,
        >,
    >,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            locks: Default::default(),
            files: Vec::new(),
            accounts: RwLock::new(Default::default()),
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
                        let mut accounts = self.accounts.write().await;
                        let vaults = accounts
                            .entry(owner)
                            .or_insert(Default::default());
                        for vault_entry in std::fs::read_dir(&path)? {
                            let vault_entry = vault_entry?;
                            let vault_path = vault_entry.path();
                            if let Some(ext) = vault_path.extension() {
                                if ext == Vault::extension() {
                                    let summary = Header::read_summary_file(
                                        &vault_path,
                                    )?;

                                    let mut wal_path = vault_path.clone();
                                    wal_path.set_extension(WAL_EXT);
                                    let wal_exists = wal_path.exists();

                                    let mut wal_file =
                                        WalFile::new(&wal_path)?;

                                    if !wal_exists {
                                        let event = WalEvent::CreateVault(
                                            Cow::Owned(std::fs::read(
                                                &vault_path,
                                            )?),
                                        );
                                        wal_file.append_event(event)?;
                                    }

                                    self.files.push(wal_path);
                                    self.files.push(vault_path.to_path_buf());
                                    vaults.insert(
                                        *summary.id(),
                                        (
                                            Box::new(VaultFileAccess::new(
                                                vault_path,
                                            )?),
                                            Box::new(wal_file),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn vault_file_path(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> PathBuf {
        let account_dir = self.directory.join(owner.to_string());
        let mut vault_file = account_dir.join(vault_id.to_string());
        vault_file.set_extension(Vault::extension());
        vault_file
    }

    /// Write a vault file to disc for the given owner address.
    async fn new_vault_file(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<PathBuf> {
        let vault_file = self.vault_file_path(owner, vault_id);
        if vault_file.exists() {
            return Err(Error::FileExists(vault_file));
        }

        tokio::fs::write(&vault_file, vault).await?;

        Ok(vault_file)
    }

    /// Add a vault file path to the in-memory account.
    async fn add_vault_path(
        &mut self,
        owner: AddressStr,
        vault_path: PathBuf,
        vault: &[u8],
    ) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        let vaults = accounts.entry(owner).or_insert(Default::default());
        let summary = Header::read_summary_file(&vault_path)?;

        let mut wal_path = vault_path.clone();
        wal_path.set_extension(WAL_EXT);
        let mut wal_file = WalFile::new(&wal_path)?;
        let event = WalEvent::CreateVault(Cow::Borrowed(vault));
        wal_file.append_event(event)?;

        self.locks.add(&wal_path)?;
        self.locks.add(&vault_path)?;

        vaults.insert(
            *summary.id(),
            (
                Box::new(VaultFileAccess::new(vault_path)?),
                Box::new(wal_file),
            ),
        );

        Ok(())
    }
}

#[async_trait]
impl Backend for FileSystemBackend {
    fn set_file_locks(&mut self, mut locks: FileLocks) -> Result<()> {
        for file in &self.files {
            locks.add(file)?;
        }
        self.locks = locks;
        Ok(())
    }

    fn file_locks(&self) -> &FileLocks {
        &self.locks
    }

    async fn create_account(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if account_dir.exists() {
            return Err(Error::DirectoryExists(account_dir));
        }

        // Check it looks like a vault payload
        Header::read_summary_slice(vault)?;

        tokio::fs::create_dir(account_dir).await?;
        let vault_path = self.new_vault_file(owner, vault_id, vault).await?;
        self.add_vault_path(*owner, vault_path, vault).await?;

        Ok(())
    }

    async fn create_vault(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        // Check it looks like a vault payload
        Header::read_summary_slice(vault)?;

        let vault_path = self.new_vault_file(owner, vault_id, vault).await?;
        self.add_vault_path(*owner, vault_path, vault).await?;

        Ok(())
    }

    async fn delete_vault(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        let mut accounts = self.accounts.write().await;
        if accounts.get(owner).is_none() {
            return Err(Error::AccountNotExist(*owner));
        }

        let account = accounts.get_mut(owner).unwrap();
        if account.get(vault_id).is_none() {
            return Err(Error::VaultNotExist(*vault_id));
        }

        let removed = account.remove(vault_id);
        if let Some(_) = removed {
            let vault_path = self.vault_file_path(&owner, vault_id);
            let mut wal_path = vault_path.clone();
            wal_path.set_extension(WAL_EXT);

            self.locks.remove(&wal_path)?;
            self.locks.remove(&vault_path)?;

            let _ = tokio::fs::remove_file(&vault_path).await;

            // Keep a backup of the WAL file as .wal.deleted
            let mut wal_backup = wal_path.clone();
            wal_backup.set_extension(WAL_DELETED_EXT);
            let _ = tokio::fs::rename(wal_path, wal_backup).await?;
        }

        Ok(())
    }

    async fn account_exists(&self, owner: &AddressStr) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        let accounts = self.accounts.read().await;
        accounts.get(owner).is_some() && account_dir.is_dir()
    }

    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            for (_, (storage, _)) in account {
                summaries.push(storage.summary()?);
            }
        }
        Ok(summaries)
    }

    async fn vault_exists(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<(bool, u32)> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            if let Some((storage, _)) = account.get(vault_id) {
                Ok((true, storage.change_seq()?))
            } else {
                Ok((false, 0))
            }
        } else {
            Ok((false, 0))
        }
    }

    async fn get(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            if let Some(_) = account.get(vault_id) {
                let vault_file = self.vault_file_path(owner, vault_id);
                let buffer = tokio::fs::read(vault_file).await?;
                return Ok(buffer);
            }
        } else {
            return Err(Error::AccountNotExist(*owner));
        }
        Err(Error::VaultNotExist(*vault_id))
    }

    async fn vault_read<'a>(
        &'a self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<RwLockReadGuard<'a, VaultStorage>> {
        let accounts = self.accounts.read().await;
        if accounts.get(owner).is_none() {
            return Err(Error::AccountNotExist(*owner));
        }

        let account = accounts.get(owner).unwrap();
        if account.get(vault_id).is_none() {
            return Err(Error::VaultNotExist(*vault_id));
        }

        let guard = RwLockReadGuard::map(accounts, |accounts| {
            let account = accounts.get(owner).unwrap();
            &account.get(vault_id).unwrap().0
        });

        Ok(guard)
    }

    async fn vault_write<'a>(
        &'a mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<RwLockMappedWriteGuard<'a, VaultStorage>> {
        let accounts = self.accounts.write().await;
        if accounts.get(owner).is_none() {
            return Err(Error::AccountNotExist(*owner));
        }

        let account = accounts.get(owner).unwrap();
        if account.get(vault_id).is_none() {
            return Err(Error::VaultNotExist(*vault_id));
        }

        let guard = RwLockWriteGuard::map(accounts, |accounts| {
            let account = accounts.get_mut(owner).unwrap();
            &mut account.get_mut(vault_id).unwrap().0
        });

        Ok(guard)
    }
}
