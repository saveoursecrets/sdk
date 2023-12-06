//! File system paths for application level folders
//! and user-specific account folders.
use crate::{Error, Result};
use app_dirs2::{get_app_root, AppDataType, AppInfo};
use async_once_cell::OnceCell;
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        ACCOUNT_EVENTS, APP_AUTHOR, APP_NAME, AUDIT_FILE_NAME, DEVICES_DIR,
        EVENT_LOG_EXT, FILES_DIR, FILE_EVENTS, IDENTITY_DIR, JSON_EXT,
        LOCAL_DIR, LOGS_DIR, PREFERENCES_FILE, REMOTES_FILE, TEMP_DIR,
        VAULTS_DIR, VAULT_EXT,
    },
    events::{AuditEvent, AuditLogFile, AuditProvider},
    vault::{secret::SecretId, VaultId},
    vfs,
};
use tokio::sync::Mutex;

const APP_INFO: AppInfo = AppInfo {
    name: APP_NAME,
    author: APP_AUTHOR,
};

static shared: OnceCell<Mutex<AuditLogFile>> = OnceCell::new();

static DATA_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

/// Encapsulates the paths for a user account.
#[derive(Default, Debug, Clone)]
pub struct UserPaths {
    /// User identifier.
    user_id: String,
    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// Directory for identity vaults.
    identity_dir: PathBuf,
    /// Directory for local storage.
    local_dir: PathBuf,
    /// Directory for application logs.
    logs_dir: PathBuf,
    /// Directory for temporary storage.
    temp_dir: PathBuf,
    /// File for local audit logs.
    audit_file: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// User file storage.
    files_dir: PathBuf,
    /// User vault storage.
    vaults_dir: PathBuf,
    /// User devices storage.
    devices_dir: PathBuf,
}

impl UserPaths {
    /// Create new paths.
    pub fn new<D: AsRef<Path>>(
        documents_dir: D,
        user_id: impl AsRef<str>,
    ) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(LOCAL_DIR);
        let logs_dir = documents_dir.join(LOGS_DIR);
        let identity_dir = documents_dir.join(IDENTITY_DIR);
        let audit_file = local_dir.join(AUDIT_FILE_NAME);
        let temp_dir = local_dir.join(TEMP_DIR);
        let user_dir = local_dir.join(user_id.as_ref());
        let files_dir = user_dir.join(FILES_DIR);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        let devices_dir = user_dir.join(DEVICES_DIR);

        Self {
            user_id: user_id.as_ref().to_owned(),
            documents_dir,
            identity_dir,
            local_dir,
            logs_dir,
            temp_dir,
            audit_file,
            user_dir,
            files_dir,
            vaults_dir,
            devices_dir,
        }
    }

    /// Create new paths with an empty user identifier.
    ///
    /// Used to get application level paths when a user identifier
    /// is not available.
    pub fn new_global<D: AsRef<Path>>(documents_dir: D) -> Self {
        Self::new(documents_dir, "")
    }

    /// Ensure all the user directories exist.
    pub async fn ensure(&self) -> Result<()> {
        vfs::create_dir_all(&self.documents_dir).await?;
        //vfs::create_dir_all(&self.identity_dir).await?;
        vfs::create_dir_all(&self.local_dir).await?;
        //vfs::create_dir_all(&self.logs_dir).await?;
        vfs::create_dir_all(&self.user_dir).await?;
        vfs::create_dir_all(&self.files_dir).await?;
        vfs::create_dir_all(&self.vaults_dir).await?;
        vfs::create_dir_all(&self.devices_dir).await?;
        Ok(())
    }

    /// Get the documents storage directory.
    pub fn documents_dir(&self) -> &PathBuf {
        &self.documents_dir
    }

    /// Get the path to the identity vault file for this account.
    pub fn identity_dir(&self) -> &PathBuf {
        &self.identity_dir
    }

    /// Get the path to the local storage.
    pub fn local_dir(&self) -> &PathBuf {
        &self.local_dir
    }

    /// Get the app logs directory.
    pub fn logs_dir(&self) -> &PathBuf {
        &self.logs_dir
    }

    /// Get the temporary directory.
    pub fn temp_dir(&self) -> &PathBuf {
        &self.temp_dir
    }

    /// Audit file location.
    pub fn audit_file(&self) -> &PathBuf {
        &self.audit_file
    }

    /// Get the user storage directory.
    pub fn user_dir(&self) -> &PathBuf {
        &self.user_dir
    }

    /// Get the user files directory.
    pub fn files_dir(&self) -> &PathBuf {
        &self.files_dir
    }

    /// Get the expected location for the directory containing
    /// all the external files for a folder.
    pub fn file_folder_location(&self, vault_id: &VaultId) -> PathBuf {
        self.files_dir.join(vault_id.to_string())
    }

    /// Get the expected location for a file.
    pub fn file_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: impl AsRef<str>,
    ) -> PathBuf {
        self.file_folder_location(vault_id)
            .join(secret_id.to_string())
            .join(file_name.as_ref())
    }

    /// Get the user vaults storage directory.
    pub fn vaults_dir(&self) -> &PathBuf {
        &self.vaults_dir
    }

    /// Get the user devices directory.
    pub fn devices_dir(&self) -> &PathBuf {
        &self.devices_dir
    }

    /// Get the path to the identity vault file for this account.
    pub fn identity_vault(&self) -> PathBuf {
        let mut identity_vault_file = self.identity_dir.join(&self.user_id);
        identity_vault_file.set_extension(VAULT_EXT);
        identity_vault_file
    }

    /// Get the path to a vault file from it's identifier.
    pub fn vault_path<V: AsRef<Path>>(&self, id: V) -> PathBuf {
        let mut vault_path = self.vaults_dir.join(id);
        vault_path.set_extension(VAULT_EXT);
        vault_path
    }

    /// Get the path to an event log file from it's identifier.
    pub fn event_log_path<V: AsRef<Path>>(&self, id: V) -> PathBuf {
        let mut vault_path = self.vaults_dir.join(id);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Get the path to the account event log file.
    pub fn account_events(&self) -> PathBuf {
        let mut vault_path = self.user_dir.join(ACCOUNT_EVENTS);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Get the path to the event log file that records
    /// changes to external files.
    pub fn file_events(&self) -> PathBuf {
        let mut vault_path = self.user_dir.join(FILE_EVENTS);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Get the path to the file used to store remote origins.
    pub fn remote_origins(&self) -> PathBuf {
        let mut vault_path = self.user_dir.join(REMOTES_FILE);
        vault_path.set_extension(JSON_EXT);
        vault_path
    }

    /// Get the path to the account preferences.
    pub fn preferences(&self) -> PathBuf {
        let mut vault_path = self.user_dir.join(PREFERENCES_FILE);
        vault_path.set_extension(JSON_EXT);
        vault_path
    }

    /// Helper to get paths for an optional data directory
    /// and ensure the paths exist on disc.
    pub async fn ensure_paths(
        address: impl AsRef<str>,
        data_dir: Option<PathBuf>,
    ) -> Result<UserPaths> {
        // Ensure all paths before sign_in
        let paths = if let Some(data_dir) = data_dir {
            UserPaths::new(data_dir, address)
        } else {
            UserPaths::new(UserPaths::data_dir()?, address)
        };
        paths.ensure().await?;
        Ok(paths)
    }

    /// Ensure the root directories exist.
    pub async fn scaffold(data_dir: Option<PathBuf>) -> Result<()> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            UserPaths::data_dir()?
        };
        let paths = Self::new_global(data_dir);
        vfs::create_dir_all(paths.documents_dir()).await?;
        vfs::create_dir_all(paths.identity_dir()).await?;
        vfs::create_dir_all(paths.logs_dir()).await?;
        Ok(())
    }

    /// Set an explicit data directory used to store all
    /// application files.
    pub fn set_data_dir(path: PathBuf) {
        let mut writer = DATA_DIR.write().unwrap();
        *writer = Some(path);
    }

    /// Clear an explicitly set data directory.
    pub fn clear_data_dir() {
        let mut writer = DATA_DIR.write().unwrap();
        *writer = None;
    }

    /// Get the default root directory used for caching application data.
    ///
    /// If the `SOS_DATA_DIR` environment variable is set it is used.
    ///
    /// Otherwise if an explicit directory has been set
    /// using `set_data_dir()` then that will be used instead.
    ///
    /// Finally if no environment variable or explicit directory has been
    /// set then a path will be computed by platform convention.
    ///
    /// When running with `debug_assertions` a `debug` path is appended
    /// (except when executing tests) so that we can use different
    /// storage locations for debug and release builds.
    ///
    /// If the `SOS_TEST` environment variable is set then we use
    /// `test` rather than `debug` as the nested directory so that
    /// test data does not collide with debug data.
    pub fn data_dir() -> Result<PathBuf> {
        let dir = if let Ok(env_data_dir) = std::env::var("SOS_DATA_DIR") {
            Ok(PathBuf::from(env_data_dir))
        } else {
            let reader = DATA_DIR.read().unwrap();
            if let Some(explicit) = reader.as_ref() {
                Ok(explicit.to_path_buf())
            } else {
                default_storage_dir()
            }
        };

        let has_explicit_env = std::env::var("SOS_DATA_DIR").ok().is_some();
        if cfg!(debug_assertions) && !has_explicit_env {
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

    /// Append to the audit log.
    pub async fn append_audit_events(
        &self,
        events: Vec<AuditEvent>,
    ) -> Result<()> {
        let log_file = shared
            .get_or_init(async move {
                println!("INITIALIZE AUDIT FILE IN {:#?}", self.audit_file());
                Mutex::new(
                    AuditLogFile::new(self.audit_file())
                        .await
                        .expect("could not create audit log file"),
                )
            })
            .await;
        let mut writer = log_file.lock().await;
        writer.append_audit_events(events).await?;
        Ok(())
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
