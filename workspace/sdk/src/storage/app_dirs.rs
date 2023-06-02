//! File system paths for the application.
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        DEVICES_DIR, EVENT_LOG_EXT, FILES_DIR, IDENTITY_DIR, LOCAL_DIR,
        TEMP_DIR, TRASH_DIR, VAULTS_DIR, VAULT_EXT,
    },
    vfs,
};

static CACHE_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

/// Encapsulates the paths for an application.
#[derive(Default, Debug)]
pub struct AppDirs;

impl AppDirs {
    /// Ensure the skeleton directories exist.
    pub async fn skeleton() -> Result<()> {
        if let Some(cache_dir) = Self::cache_dir() {
            vfs::create_dir_all(&cache_dir).await?;

            let identity_dir = cache_dir.join(IDENTITY_DIR);
            vfs::create_dir_all(&identity_dir).await?;
        }
        Ok(())
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

    /// Get the path to the directory used to store identity vaults.
    pub fn identity_dir() -> Result<PathBuf> {
        let cache_dir = Self::cache_dir().ok_or(Error::NoCache)?;
        let identity_dir = cache_dir.join(IDENTITY_DIR);
        Ok(identity_dir)
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
    #[deprecated]
    pub fn devices_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(DEVICES_DIR))
    }

    /// Get the local directory for storing vaults.
    #[deprecated]
    pub fn local_vaults_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(VAULTS_DIR))
    }

    /// Get the path to a vault file from it's identifier.
    #[deprecated]
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
    #[deprecated]
    pub fn log_path<A: AsRef<Path>, V: AsRef<Path>>(
        address: A,
        id: V,
    ) -> Result<PathBuf> {
        let vaults_dir = Self::local_vaults_dir(address)?;
        let mut vault_path = vaults_dir.join(id);
        vault_path.set_extension(EVENT_LOG_EXT);
        Ok(vault_path)
    }

    /// Get the path to the directory used to store files.
    ///
    /// Ensure it exists if it does not already exist.
    #[deprecated]
    pub fn files_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let files_dir = local_dir.join(address).join(FILES_DIR);
        Ok(files_dir)
    }

    /// Get the expected location for the directory containing
    /// all the external files for a folder.
    #[deprecated]
    pub fn file_folder_location<A: AsRef<Path>, V: AsRef<Path>>(
        address: A,
        vault_id: V,
    ) -> Result<PathBuf> {
        let path = Self::files_dir(address)?.join(vault_id);
        Ok(path)
    }

    /// Get the expected location for a file.
    #[deprecated]
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

    /// Get the path to the identity vault file for an account identifier.
    #[deprecated(note = "Use identity() instead")]
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
