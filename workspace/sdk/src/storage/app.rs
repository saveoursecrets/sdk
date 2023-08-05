//! File system paths for the application.
use crate::{Error, Result};
use app_dirs2::{get_app_root, AppDataType, AppInfo};
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        APP_AUTHOR, APP_NAME, DEVICES_DIR, EVENT_LOG_EXT, FILES_DIR,
        IDENTITY_DIR, LOCAL_DIR, TEMP_DIR, TRASH_DIR, VAULTS_DIR, VAULT_EXT,
    },
    vfs,
};

const APP_INFO: AppInfo = AppInfo {
    name: APP_NAME,
    author: APP_AUTHOR,
};

static CACHE_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

/// Encapsulates the paths for an application.
#[derive(Default, Debug)]
pub struct AppPaths;

impl AppPaths {
    /// Ensure the root directories exist.
    pub async fn scaffold() -> Result<()> {
        let data_dir = Self::data_dir()?;
        vfs::create_dir_all(&data_dir).await?;
        let identity_dir = data_dir.join(IDENTITY_DIR);
        vfs::create_dir_all(&identity_dir).await?;
        Ok(())
    }

    /// Set an explicit cache directory.
    pub fn set_data_dir(path: PathBuf) {
        let mut writer = CACHE_DIR.write().unwrap();
        *writer = Some(path);
    }

    /// Clear an explicit cache directory.
    ///
    /// Primarily used for testing purposes.
    pub fn clear_data_dir() {
        let mut writer = CACHE_DIR.write().unwrap();
        *writer = None;
    }

    /// Get the default root directory used for caching client data.
    ///
    /// If the `SOS_DATA_DIR` environment variable is set it is used.
    ///
    /// Otherwise if an explicit directory has been set
    /// using `set_data_dir()` then that will be used instead.
    ///
    /// Finally if no environment variable or explicit directory has been
    /// set then a path will be computed by platform convention.
    ///
    /// When running in with `debug_assertions` a `debug` path is appended
    /// so that we can use different storage locations for debug and
    /// release builds.
    pub fn data_dir() -> Result<PathBuf> {
        let dir = if let Ok(env_data_dir) = std::env::var("SOS_DATA_DIR") {
            Ok(PathBuf::from(env_data_dir))
        } else {
            let reader = CACHE_DIR.read().unwrap();
            if let Some(explicit) = reader.as_ref() {
                Ok(explicit.to_path_buf())
            } else {
                default_storage_dir()
            }
        };
        if cfg!(debug_assertions) {
            let sub_dir = if std::env::var("SOS_TEST").is_ok() {
                "test"
            } else {
                "debug"
            };
            dir.map(|dir| dir.join(sub_dir))
        } else {
            dir
        }
    }

    /// Get the path to the directory used to store identity vaults.
    pub fn identity_dir() -> Result<PathBuf> {
        let data_dir = Self::data_dir()?;
        let identity_dir = data_dir.join(IDENTITY_DIR);
        Ok(identity_dir)
    }

    /// Get the local cache directory.
    pub fn local_dir() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join(LOCAL_DIR))
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

    /// Get the local directory for storing vaults.
    pub fn local_vaults_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(VAULTS_DIR))
    }

    /// Get the path to the directory used to store files.
    ///
    /// Ensure it exists if it does not already exist.
    pub fn files_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let files_dir = local_dir.join(address).join(FILES_DIR);
        Ok(files_dir)
    }

    /// Get the local directory for storing devices.
    pub fn devices_dir<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        Ok(local_dir.join(address).join(DEVICES_DIR))
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

    /// Get the path to the identity vault file for an account identifier.
    pub fn identity_vault<A: AsRef<Path>>(address: A) -> Result<PathBuf> {
        let identity_dir = Self::identity_dir()?;
        let mut identity_vault_file = identity_dir.join(address.as_ref());
        identity_vault_file.set_extension(VAULT_EXT);
        Ok(identity_vault_file)
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
        vault_path.set_extension(EVENT_LOG_EXT);
        Ok(vault_path)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn default_storage_dir() -> Result<PathBuf> {
    Ok(get_app_root(AppDataType::UserData, &APP_INFO)
        .map_err(|_| Error::NoCache)?)
}

#[cfg(target_arch = "wasm32")]
fn default_storage_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(""))
}
