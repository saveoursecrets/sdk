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
    /// List vault identifiers for an account.
    fn list(&self, owner: &AddressStr) -> Option<Vec<&Uuid>>;

    /// Load a vault for an account.
    fn get(&self, owner: &AddressStr, id: &Uuid) -> Result<Option<Vault>>;

    /*
    /// Get a mutable vault.
    //fn get_mut(&mut self, id: &Uuid) -> Option<&mut Vault>;

    /// Flush the identified vault to backing storage.
    //async fn flush(&self, id: &Uuid) -> Result<()>;
    */
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
                                    let uuid = Header::read_uuid(&vault_path)?;
                                    vaults.insert(uuid, vault_path);
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

    //fn get_mut(&mut self, id: &Uuid) -> Option<&mut Vault> {
    //self.vaults.get_mut(id).map(|r| &mut r.1)
    //}

    /*
    // FIXME: lock while writing
    async fn flush(&self, id: &Uuid) -> Result<()> {
        if let Some((path, vault)) = self.vaults.get(id) {
            vault.write_file(path)?;
            return Ok(());
        }
        Err(Error::NotExist(*id))
    }
    */
}
