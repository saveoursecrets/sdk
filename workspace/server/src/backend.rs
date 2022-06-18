use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    crypto::AeadPack,
    file_access::VaultFileAccess,
    operations::VaultAccess,
    vault::{Header, Summary, Vault},
};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use tokio::sync::{
    RwLock, RwLockMappedWriteGuard, RwLockReadGuard, RwLockWriteGuard,
};
use uuid::Uuid;

type VaultStorage = Box<dyn VaultAccess + Send + Sync>;

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// Create a new account with the given default vault.
    ///
    /// The owner directory must not exist.
    async fn create_account(
        &mut self,
        owner: AddressStr,
        vault_id: Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Create a new vault.
    ///
    /// The owner directory must already exist.
    async fn create_vault(
        &mut self,
        owner: AddressStr,
        vault_id: Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &AddressStr) -> bool;

    /// List vaults for an account.
    ///
    /// Callers should ensure the account exists before attempting to
    /// list the the vaults for an account.
    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>>;

    /// Determine if a vault exists.
    async fn vault_exists(&self, owner: &AddressStr, vault_id: &Uuid) -> bool;

    /// Load a vault buffer for an account.
    async fn get(&self, owner: &AddressStr, vault_id: &Uuid)
        -> Result<Vec<u8>>;

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
    accounts:
        RwLock<HashMap<AddressStr, HashMap<Uuid, (VaultStorage, Summary)>>>,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
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
                        let vaults =
                            accounts.entry(owner).or_insert(Default::default());
                        for vault_entry in std::fs::read_dir(&path)? {
                            let vault_entry = vault_entry?;
                            let vault_path = vault_entry.path();
                            if let Some(ext) = vault_path.extension() {
                                if ext == Vault::extension() {
                                    let summary =
                                        Header::read_summary_file(&vault_path)?;
                                    vaults.insert(
                                        *summary.id(),
                                        (
                                            Box::new(VaultFileAccess::new(
                                                vault_path,
                                            )?),
                                            summary,
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

    fn vault_file_path(&self, owner: &AddressStr, vault_id: &Uuid) -> PathBuf {
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
    ) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        let vaults = accounts.entry(owner).or_insert(Default::default());
        let summary = Header::read_summary_file(&vault_path)?;
        vaults.insert(
            *summary.id(),
            (Box::new(VaultFileAccess::new(vault_path)?), summary),
        );
        Ok(())
    }
}

#[async_trait]
impl Backend for FileSystemBackend {
    async fn create_account(
        &mut self,
        owner: AddressStr,
        vault_id: Uuid,
        vault: &[u8],
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if account_dir.exists() {
            return Err(Error::DirectoryExists(account_dir));
        }

        // Check it looks like a vault payload
        Header::read_summary_slice(vault)?;

        tokio::fs::create_dir(account_dir).await?;
        let vault_path = self.new_vault_file(&owner, &vault_id, vault).await?;
        self.add_vault_path(owner, vault_path).await?;

        Ok(())
    }

    async fn create_vault(
        &mut self,
        owner: AddressStr,
        vault_id: Uuid,
        vault: &[u8],
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if !account_dir.is_dir() {
            return Err(Error::NotDirectory(account_dir));
        }

        // TODO: verify bytes looks like a vault file

        let vault_path = self.new_vault_file(&owner, &vault_id, vault).await?;
        self.add_vault_path(owner, vault_path).await?;

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
            for (_, (_, summary)) in account {
                summaries.push(summary.clone());
            }
        }
        Ok(summaries)
    }

    async fn vault_exists(&self, owner: &AddressStr, vault_id: &Uuid) -> bool {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            account.get(vault_id).is_some()
        } else {
            false
        }
    }

    async fn get(
        &self,
        owner: &AddressStr,
        vault_id: &Uuid,
    ) -> Result<Vec<u8>> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            if let Some((_, _)) = account.get(vault_id) {
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
            let (vault_file, _) = account.get(vault_id).unwrap();
            vault_file
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
            let (vault_file, _) = account.get_mut(vault_id).unwrap();
            vault_file
        });

        Ok(guard)
    }
}
