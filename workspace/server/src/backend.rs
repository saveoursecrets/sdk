use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    vault::{Header, Summary, Vault},
};
use std::{collections::HashMap, path::PathBuf};
use uuid::Uuid;

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// Create a new account.
    async fn create_account(
        &mut self,
        owner: AddressStr,
        uuid: Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Determine if an account exists for the given address.
    async fn account_exists(&self, owner: &AddressStr) -> bool;

    /// List vaults for an account.
    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>>;

    /// Determine if an vault exists for the given address and uuid.
    async fn vault_exists(&self, owner: &AddressStr, uuid: &Uuid) -> bool;

    /// Load a vault buffer for an account.
    async fn get(&self, owner: &AddressStr, uuid: &Uuid) -> Result<Vec<u8>>;
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    accounts: HashMap<AddressStr, HashMap<Uuid, PathBuf>>,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            accounts: Default::default(),
        }
    }

    /// Read accounts and vault file paths into memory.
    pub fn read_dir(&mut self) -> Result<()> {
        if !self.directory.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }

        let mut accounts: HashMap<AddressStr, HashMap<Uuid, PathBuf>> =
            HashMap::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<AddressStr>()
                    {
                        let vaults =
                            accounts.entry(owner).or_insert(Default::default());
                        for vault_entry in std::fs::read_dir(&path)? {
                            let vault_entry = vault_entry?;
                            let vault_path = vault_entry.path();
                            if let Some(ext) = vault_path.extension() {
                                if ext == Vault::extension() {
                                    let summary =
                                        Header::read_summary(&vault_path)?;
                                    vaults.insert(*summary.id(), vault_path);
                                }
                            }
                        }
                    }
                }
            }
        }
        self.accounts = accounts;
        Ok(())
    }
}

#[async_trait]
impl Backend for FileSystemBackend {
    async fn create_account(
        &mut self,
        owner: AddressStr,
        uuid: Uuid,
        vault: &[u8],
    ) -> Result<()> {
        let account_dir = self.directory.join(owner.to_string());
        if account_dir.exists() {
            return Err(Error::DirectoryExists(account_dir));
        }

        let mut vault_file = account_dir.join(uuid.to_string());
        vault_file.set_extension(Vault::extension());
        if vault_file.exists() {
            return Err(Error::FileExists(vault_file));
        }

        tokio::fs::create_dir(account_dir).await?;
        tokio::fs::write(vault_file, vault).await?;

        Ok(())
    }

    async fn account_exists(&self, owner: &AddressStr) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        account_dir.exists()
    }

    async fn list(&self, owner: &AddressStr) -> Result<Vec<Summary>> {
        let mut summaries = Vec::new();
        let account_dir = self.directory.join(owner.to_string());
        let mut stream = tokio::fs::read_dir(&account_dir).await?;
        while let Some(entry) = stream.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == Vault::extension() {
                    let summary = Header::read_summary(&path)?;
                    summaries.push(summary);
                }
            }
        }
        Ok(summaries)
    }

    async fn vault_exists(&self, owner: &AddressStr, uuid: &Uuid) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        let mut vault_file = account_dir.join(uuid.to_string());
        vault_file.set_extension(Vault::extension());
        vault_file.exists()
    }

    async fn get(&self, owner: &AddressStr, uuid: &Uuid) -> Result<Vec<u8>> {
        let account_dir = self.directory.join(owner.to_string());
        let mut vault_file = account_dir.join(uuid.to_string());
        vault_file.set_extension(Vault::extension());
        let buffer = tokio::fs::read(&vault_file).await?;
        Ok(buffer)
    }
}
