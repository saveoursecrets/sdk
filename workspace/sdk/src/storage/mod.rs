//! File system paths and encrypted file storage.
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        DEVICES_DIR, FILES_DIR, IDENTITY_DIR, LOCAL_DIR, TEMP_DIR, TRASH_DIR,
        VAULTS_DIR, VAULT_EXT, WAL_EXT,
    },
    vfs,
};

static CACHE_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

mod external_files;

pub use external_files::{EncryptedFile, FileStorage};

/// Compute the file name from a path.
///
/// If no file name is available the returned value is the
/// empty string.
pub fn basename<P: AsRef<Path>>(path: P) -> String {
    path.as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Guess the MIME type of a path.
///
/// This implementation supports some more types
/// that are not in the the mime_guess library that
/// we also want to recognize.
pub fn guess_mime<P: AsRef<Path>>(path: P) -> Result<String> {
    if let Some(extension) = path.as_ref().extension() {
        let fixed = match extension.to_string_lossy().as_ref() {
            "heic" => Some("image/heic".to_string()),
            "heif" => Some("image/heif".to_string()),
            "avif" => Some("image/avif".to_string()),
            _ => None,
        };

        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
    }
    let mime = mime_guess::from_path(&path)
        .first_or(mime_guess::mime::APPLICATION_OCTET_STREAM)
        .to_string();
    Ok(mime)
}

/// Encapsulates the paths for vault storage.
#[derive(Default, Debug)]
pub struct StorageDirs {
    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// Directory for local storage.
    local_dir: PathBuf,
    /// Trash for deleted data.
    trash_dir: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// User file storage.
    files_dir: PathBuf,
    /// User vault storage.
    vaults_dir: PathBuf,
}

impl StorageDirs {
    /// Create new storage dirs.
    pub fn new<D: AsRef<Path>>(documents_dir: D, user_id: &str) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(LOCAL_DIR);
        let trash_dir = local_dir.join(TRASH_DIR);
        let user_dir = local_dir.join(user_id);
        let files_dir = user_dir.join(FILES_DIR);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        Self {
            documents_dir,
            local_dir,
            trash_dir,
            user_dir,
            files_dir,
            vaults_dir,
        }
    }

    /// Ensure all the directories exist.
    pub async fn ensure(&self) -> Result<()> {
        if let Some(cache_dir) = Self::cache_dir() {
            vfs::create_dir_all(&cache_dir).await?;

            let identity_dir = cache_dir.join(IDENTITY_DIR);
            vfs::create_dir_all(&identity_dir).await?;
        }

        vfs::create_dir_all(&self.documents_dir).await?;
        vfs::create_dir_all(&self.local_dir).await?;
        vfs::create_dir_all(&self.trash_dir).await?;
        vfs::create_dir_all(&self.user_dir).await?;
        vfs::create_dir_all(&self.files_dir).await?;
        vfs::create_dir_all(&self.vaults_dir).await?;

        let identity_dir = Self::identity_dir()?;
        if !identity_dir.exists() {
            vfs::create_dir(&identity_dir).await?;
        }

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
    pub fn set_cache_dir(path: PathBuf) {
        let mut writer = CACHE_DIR.write().unwrap();
        *writer = Some(path);
    }

    /// Clear an explicit cache directory.
    ///
    /// Primarily used for testing purposes.
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

        dir
    }

    /// Get the local cache directory.
    pub fn local_dir() -> Result<PathBuf> {
        Ok(Self::cache_dir().ok_or(Error::NoCache)?.join(LOCAL_DIR))
    }

    /// Get the trash directory.
    pub fn trash_dir() -> Result<PathBuf> {
        let trash = Self::local_dir()?.join(TRASH_DIR);
        Ok(trash)
    }

    /// Get the temporary directory.
    pub fn temp_dir() -> Result<PathBuf> {
        Ok(Self::local_dir()?.join(TEMP_DIR))
    }

    /// Get the local directory for storing devices.
    pub fn devices_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(DEVICES_DIR))
    }

    /// Get the local directory for storing vaults.
    pub fn local_vaults_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(VAULTS_DIR))
    }

    /// Get the path to a vault file from it's identifier.
    pub fn vault_path<A: AsRef<Path>, V: AsRef<Path>>(
        address: A,
        id: V,
    ) -> Result<PathBuf> {
        let vaults_dir = Self::local_vaults_dir(address)?;
        let mut vault_path = vaults_dir.join(id);
        vault_path.set_extension(VAULT_EXT);
        Ok(vault_path)
    }

    /// Get the path to a log file from it's identifier.
    pub fn log_path<A: AsRef<Path>, V: AsRef<Path>>(
        address: A,
        id: V,
    ) -> Result<PathBuf> {
        let vaults_dir = Self::local_vaults_dir(address)?;
        let mut vault_path = vaults_dir.join(id);
        vault_path.set_extension(WAL_EXT);
        Ok(vault_path)
    }

    /// Get the path to the directory used to store files.
    ///
    /// Ensure it exists if it does not already exist.
    pub fn files_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let files_dir = local_dir.join(address).join(FILES_DIR);
        Ok(files_dir)
    }

    /// Get the expected location for the directory containing
    /// all the external files for a folder.
    pub fn file_folder_location<A: AsRef<Path>, V: AsRef<Path>>(
        address: A,
        vault_id: V,
    ) -> Result<PathBuf> {
        let path = Self::files_dir(address)?.join(vault_id);
        Ok(path)
    }

    /// Get the expected location for a file.
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
        let path = Self::file_folder_location(address, vault_id)?
            .join(secret_id)
            .join(file_name);
        Ok(path)
    }

    /// Get the path to the directory used to store identity vaults.
    ///
    /// Ensure it exists if it does not already exist.
    pub fn identity_dir() -> Result<PathBuf> {
        let cache_dir = StorageDirs::cache_dir().ok_or(Error::NoCache)?;
        let identity_dir = cache_dir.join(IDENTITY_DIR);
        Ok(identity_dir)
    }

    /// Get the path to the identity vault file for an account identifier.
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

#[cfg(target_arch = "wasm32")]
fn default_storage_dir() -> Option<PathBuf> {
    Some(PathBuf::from(""))
}

fn fallback_storage_dir() -> Option<PathBuf> {
    use crate::constants::BUNDLE_ID;
    dirs::data_local_dir().map(|dir| dir.join(BUNDLE_ID))
}
