use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    address::AddressStr,
    vault::{Header, Vault},
};
use std::{collections::HashMap, fs::read_dir, path::PathBuf};
use uuid::Uuid;

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// Create a new account.
    fn create_account(
        &mut self,
        owner: AddressStr,
        uuid: Uuid,
        vault: &[u8],
    ) -> Result<()>;

    /// Determine if an account exists for the given address.
    fn account_exists(&self, owner: &AddressStr) -> bool;

    /// List vault identifiers for an account.
    fn list(&self, owner: &AddressStr) -> Option<Vec<&Uuid>>;

    /// Load a vault for an account.
    fn get(&self, owner: &AddressStr, id: &Uuid) -> Result<Option<Vault>>;
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
        for entry in read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<AddressStr>()
                    {
                        let vaults =
                            accounts.entry(owner).or_insert(Default::default());
                        for vault_entry in read_dir(&path)? {
                            let vault_entry = vault_entry?;
                            let vault_path = vault_entry.path();
                            if let Some(ext) = vault_path.extension() {
                                if ext == Vault::extension() {
                                    let summary = Header::read_summary(&vault_path)?;
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
    fn create_account(
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

        println!("creating account dir {:#?}", account_dir);
        println!("writing vault file {:#?}", vault_file);

        std::fs::create_dir(account_dir)?;
        std::fs::write(vault_file, vault)?;

        Ok(())
    }

    fn account_exists(&self, owner: &AddressStr) -> bool {
        let account_dir = self.directory.join(owner.to_string());
        account_dir.exists()
    }

    fn list(&self, addr: &AddressStr) -> Option<Vec<&Uuid>> {
        if let Some(vaults) = self.accounts.get(addr) {
            Some(vaults.keys().collect::<Vec<_>>())
        } else {
            None
        }
    }

    fn get(&self, addr: &AddressStr, id: &Uuid) -> Result<Option<Vault>> {
        let vault = if let Some(vaults) = self.accounts.get(addr) {
            if let Some(path) = vaults.get(id) {
                let vault = Vault::read_file(&path)?;
                Some(vault)
            } else {
                None
            }
        } else {
            None
        };
        Ok(vault)
    }
}
