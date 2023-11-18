//! File system paths for the application.
use crate::{Error, Result};
use app_dirs2::{get_app_root, AppDataType, AppInfo};
use once_cell::sync::Lazy;
use std::{
    path::{PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        APP_AUTHOR, APP_NAME,
        IDENTITY_DIR, LOGS_DIR,
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
    #[deprecated(note = "Use UserPaths::scaffold() instead")]
    pub async fn scaffold() -> Result<()> {
        let data_dir = Self::data_dir()?;
        vfs::create_dir_all(&data_dir).await?;
        let identity_dir = data_dir.join(IDENTITY_DIR);
        vfs::create_dir_all(&identity_dir).await?;
        let logs_dir = data_dir.join(LOGS_DIR);
        vfs::create_dir_all(&logs_dir).await?;
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
    ///
    /// If the `SOS_TEST` environment variable is set then we use
    /// `test` rather than `debug` as the nested directory so that
    /// test data does not collide with debug data.
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
            // Don't follow the convention for separating debug and 
            // release data when running the integration tests as it 
            // makes paths very hard to reason about when they are 
            // being explicitly set in test specs.
            if !cfg!(test) {
                let sub_dir = if std::env::var("SOS_TEST").is_ok() {
                    "test"
                } else {
                    "debug"
                };
                dir.map(|dir| dir.join(sub_dir))
            } else {
                dir
            }
        } else {
            dir
        }
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
