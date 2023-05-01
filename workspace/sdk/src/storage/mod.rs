//! File system paths and encrypted file storage.
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::constants::{
    DEVICES_DIR, FILES_DIR, IDENTITY_DIR, LOCAL_DIR, TEMP_DIR, TRASH_DIR,
    VAULTS_DIR, VAULT_EXT,
};

#[cfg(not(target_arch = "wasm32"))]
static CACHE_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

mod external_files;

pub use external_files::{EncryptedFile, FileStorage};

/// Encapsulates the paths for vault storage.
#[derive(Default, Debug)]
pub struct StorageDirs {
    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// Sub-directory for the vaults.
    vaults_dir: PathBuf,
}

impl StorageDirs {
    /// Create new storage dirs.
    pub fn new<D: AsRef<Path>>(documents_dir: D, user_id: &str) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(LOCAL_DIR);
        let user_dir = local_dir.join(user_id);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        Self {
            documents_dir,
            user_dir,
            vaults_dir,
        }
    }

    /// Ensure all the directories exist.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.vaults_dir)?;
        Ok(())
    }

    /// Get the documents storage directory.
    pub fn documents_dir(&self) -> &PathBuf {
        &self.documents_dir
    }

    /// Get the user storage directory.
    pub fn user_dir(&self) -> &PathBuf {
        &self.user_dir
    }

    /// Get the user vaults storage directory.
    pub fn vaults_dir(&self) -> &PathBuf {
        &self.vaults_dir
    }

    /// Set an explicit cache directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_cache_dir(path: PathBuf) {
        let mut writer = CACHE_DIR.write().unwrap();
        *writer = Some(path);
    }

    /// Clear an explicit cache directory.
    ///
    /// Primarily used for testing purposes.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clear_cache_dir() {
        let mut writer = CACHE_DIR.write().unwrap();
        *writer = None;
    }

    /// Get the default root directory used for caching client data.
    ///
    /// If the `SOS_CACHE_DIR` environment variable is set it is used.
    ///
    /// Otherwise is an explicit directory has been set using `set_cache_dir()`
    /// then that will be used.
    ///
    /// Finally if no environment variable or explicit directory has been
    /// set then a path will be computed by platform convention.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn cache_dir() -> Option<PathBuf> {
        let dir = if let Ok(env_cache_dir) = std::env::var("SOS_CACHE_DIR") {
            Some(PathBuf::from(env_cache_dir))
        } else {
            let reader = CACHE_DIR.read().unwrap();
            if reader.is_some() {
                Some(reader.as_ref().unwrap().to_path_buf())
            } else {
                default_storage_dir().or(fallback_storage_dir())
            }
        };

        // Try to ensure the directory exists
        dir.map(|d| {
            if !d.exists() {
                let _ = std::fs::create_dir_all(&d);
            }
            d
        })
    }

    /// Get the local cache directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir().ok_or(Error::NoCache)?.join(LOCAL_DIR))
    }

    /// Get the trash directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn trash_dir() -> Result<PathBuf> {
        let trash = Self::local_dir()?.join(TRASH_DIR);
        if !trash.exists() {
            std::fs::create_dir_all(&trash)?;
        }
        Ok(trash)
    }

    /// Get the temporary directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn temp_dir() -> Result<PathBuf> {
        Ok(Self::local_dir()?.join(TEMP_DIR))
    }

    /// Get the local directory for storing devices.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn devices_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(DEVICES_DIR))
    }

    /// Get the local directory for storing vaults.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_vaults_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(VAULTS_DIR))
    }

    /// Get the path to the directory used to store files.
    ///
    /// Ensure it exists if it does not already exist.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn files_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let files_dir = local_dir.join(address).join(FILES_DIR);
        if !files_dir.exists() {
            // Must also create parents as when we import
            // an account from an archive the parent directories
            // may not already exist
            std::fs::create_dir_all(&files_dir)?;
        }
        Ok(files_dir)
    }

    /// Get the expected location for a file.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn file_location<
        A: AsRef<Path>,
        V: AsRef<Path>,
        S: AsRef<Path>,
        F: AsRef<Path>,
    >(
        address: A,
        vault_id: V,
        secret_id: S,
        file_name: F,
    ) -> Result<PathBuf> {
        let path = Self::files_dir(address)?
            .join(vault_id)
            .join(secret_id)
            .join(file_name);
        Ok(path)
    }

    /// Get the path to the directory used to store identity vaults.
    ///
    /// Ensure it exists if it does not already exist.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn identity_dir() -> Result<PathBuf> {
        let cache_dir = StorageDirs::cache_dir().ok_or(Error::NoCache)?;
        let identity_dir = cache_dir.join(IDENTITY_DIR);
        if !identity_dir.exists() {
            std::fs::create_dir(&identity_dir)?;
        }
        Ok(identity_dir)
    }

    /// Get the path to the identity vault file for an account identifier.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn identity_vault<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let identity_dir = Self::identity_dir()?;
        let mut identity_vault_file = identity_dir.join(address.as_ref());
        identity_vault_file.set_extension(VAULT_EXT);
        Ok(identity_vault_file)
    }
}

#[cfg(target_os = "macos")]
fn default_storage_dir() -> Option<PathBuf> {
    use crate::constants::BUNDLE_ID;
    dirs::home_dir().map(|v| {
        v.join("Library")
            .join("Containers")
            .join(BUNDLE_ID)
            .join("Data")
            .join("Documents")
    })
}

#[cfg(target_os = "ios")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "android")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "linux")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "windows")]
fn default_storage_dir() -> Option<PathBuf> {
    use sos_sdk::constants::BUNDLE_ID;
    dirs::home_dir().and_then(|v| {
        let d = v.join("AppData").join("Local").join(BUNDLE_ID);
        Some(d)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn fallback_storage_dir() -> Option<PathBuf> {
    use crate::constants::BUNDLE_ID;
    dirs::data_local_dir().map(|dir| dir.join(BUNDLE_ID))
}
