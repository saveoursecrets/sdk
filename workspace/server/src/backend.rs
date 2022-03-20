use async_trait::async_trait;
use sos_core::vault::Vault;
use std::{collections::HashMap, fs::read_dir, path::PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("not a directory {0}")]
    NotDirectory(PathBuf),

    #[error("no vaults found")]
    NoVaults,

    #[error("vault {0} does not exist")]
    NotExist(Uuid),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait Backend {
    /// List vault identifiers.
    fn list(&self) -> Vec<&Uuid>;

    /// Get a vault.
    fn get(&self, id: &Uuid) -> Option<&Vault>;

    /// Get a mutable vault.
    fn get_mut(&mut self, id: &Uuid) -> Option<&mut Vault>;

    /// Flush the identified vault to backing storage.
    async fn flush(&self, id: &Uuid) -> Result<()>;
}

/// Backened storage for vaults on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    vaults: HashMap<Uuid, (PathBuf, Vault)>,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            vaults: Default::default(),
        }
    }

    /// Read vaults into memory.
    pub fn read_dir(&mut self) -> Result<()> {
        if !self.directory.is_dir() {
            return Err(BackendError::NotDirectory(self.directory.clone()));
        }

        let mut vaults = Vec::new();
        for entry in read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == Vault::extension() {
                    let vault = Vault::read_file(&path)?;
                    vaults.push((path, vault));
                }
            }
        }

        if vaults.is_empty() {
            return Err(BackendError::NoVaults);
        }

        self.vaults = vaults
            .into_iter()
            .map(|(p, v)| (v.id().clone(), (p, v)))
            .collect::<_>();

        Ok(())
    }
}

#[async_trait]
impl Backend for FileSystemBackend {
    fn list(&self) -> Vec<&Uuid> {
        self.vaults.keys().collect::<Vec<_>>()
    }

    fn get(&self, id: &Uuid) -> Option<&Vault> {
        self.vaults.get(id).map(|r| &r.1)
    }

    fn get_mut(&mut self, id: &Uuid) -> Option<&mut Vault> {
        self.vaults.get_mut(id).map(|r| &mut r.1)
    }

    // FIXME: lock while writing
    async fn flush(&self, id: &Uuid) -> Result<()> {
        if let Some((path, vault)) = self.vaults.get(id) {
            vault.write_file(path)?;
            return Ok(());
        }
        Err(BackendError::NotExist(id.clone()))
    }
}
