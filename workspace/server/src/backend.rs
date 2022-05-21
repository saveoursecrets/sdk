use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    crypto::AeadPack,
    file_access::VaultFileAccess,
    operations::Payload,
    vault::{Header, Summary, Vault},
};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use tokio::sync::RwLock;
use uuid::Uuid;

#[async_trait]
pub trait OwnedVaultAccess {
    /// Create a secret in the given vault.
    async fn create_secret(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        secret_id: Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Payload>;

    /// Read an encrypted secret from the vault.
    fn read_secret<'a>(
        &'a self,
        owner: &AddressStr,
        vault_id: &Uuid,
        secret_id: &Uuid,
    ) -> Result<(Option<Cow<'a, (AeadPack, AeadPack)>>, Payload)>;

    /// Update an encrypted secret in the vault.
    fn update_secret(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        secret_id: &Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Option<Payload>>;

    /// Remove an encrypted secret from the vault.
    fn delete_secret(
        &mut self,
        owner: &AddressStr,
        vault_id: &Uuid,
        secret_id: &Uuid,
    ) -> Result<Payload>;
}

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
}

/// Backend storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    accounts:
        RwLock<HashMap<AddressStr, HashMap<Uuid, (VaultFileAccess, Summary)>>>,
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
                                        Header::read_summary(&vault_path)?;
                                    vaults.insert(
                                        *summary.id(),
                                        (
                                            VaultFileAccess::new(vault_path)?,
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

    /// Write a vault file to disc for the given owner address.
    async fn new_vault_file(
        &mut self,
        owner: AddressStr,
        vault_id: &Uuid,
        vault: &[u8],
    ) -> Result<PathBuf> {
        let account_dir = self.directory.join(owner.to_string());
        let mut vault_file = account_dir.join(vault_id.to_string());
        vault_file.set_extension(Vault::extension());
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
        let summary = Header::read_summary(&vault_path)?;
        vaults.insert(
            *summary.id(),
            (VaultFileAccess::new(vault_path)?, summary),
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

        // TODO: verify bytes looks like a vault file

        tokio::fs::create_dir(account_dir).await?;
        let vault_path = self.new_vault_file(owner, &vault_id, vault).await?;
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

        let vault_path = self.new_vault_file(owner, &vault_id, vault).await?;
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
            if let Some((vault_file, _)) = account.get(vault_id) {
                let buffer = tokio::fs::read(vault_file.path()).await?;
                return Ok(buffer);
            }
        }
        Err(Error::NotExist(*vault_id))
    }
}
