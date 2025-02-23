//! File system paths for application level folders
//! and user-specific account folders.
use crate::{
    constants::{
        ACCOUNT_EVENTS, APP_AUTHOR, APP_NAME, AUDIT_FILE_NAME, BLOBS_DIR,
        DATABASE_FILE, DEVICE_EVENTS, DEVICE_FILE, EVENT_LOG_EXT, FILES_DIR,
        FILE_EVENTS, IDENTITY_DIR, JSON_EXT, LOCAL_DIR, LOGS_DIR,
        PREFERENCES_FILE, REMOTES_FILE, REMOTE_DIR, SYSTEM_MESSAGES_FILE,
        VAULTS_DIR, VAULT_EXT,
    },
    AccountId, Result, SecretId, VaultId,
};
#[cfg(not(target_arch = "wasm32"))]
use etcetera::{
    app_strategy::choose_native_strategy, AppStrategy, AppStrategyArgs,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sos_vfs as vfs;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

static DATA_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

/// File system paths.
///
/// Clients and servers may be configured to run on the same machine
/// and point to the same data directory so different prefixes are
/// used to distinguish.
///
/// Clients write to a `local` directory whilst servers write to a
/// `remote` directory.
///
/// Several functions require a user identifier and will panic if
/// a user identifier has not been set, see the function documentation
/// for details.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Paths {
    /// Whether these paths are for server storage.
    server: bool,
    /// User identifier.
    user_id: String,

    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// Directory for identity vaults.
    identity_dir: PathBuf,
    /// Directory for local storage.
    local_dir: PathBuf,
    /// Database file.
    database_file: PathBuf,
    /// Directory for application logs.
    logs_dir: PathBuf,
    /// File for local audit logs.
    audit_file: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// External file blob storage.
    blobs_dir: PathBuf,
    /// User file storage.
    files_dir: PathBuf,
    /// User vault storage.
    vaults_dir: PathBuf,
    /// User devices storage.
    device_file: PathBuf,
}

impl Paths {
    /// Create new paths for a client.
    #[deprecated(note = "use with_account_id")]
    pub fn new(
        documents_dir: impl AsRef<Path>,
        user_id: impl AsRef<str>,
    ) -> Self {
        Self::new_with_prefix(false, documents_dir, user_id, LOCAL_DIR)
    }

    /// Create new paths for a client with an empty user identifier.
    ///
    /// Used to get application level paths when a user identifier
    /// is not available.
    pub fn new_global(documents_dir: impl AsRef<Path>) -> Self {
        Self::new_with_prefix(false, documents_dir, "", LOCAL_DIR)
    }

    /// Create new paths for a client with an empty user identifier.
    ///
    /// Used to get application level paths when a user identifier
    /// is not available.
    pub fn new_server(documents_dir: impl AsRef<Path>) -> Self {
        Self::new_with_prefix(true, documents_dir, "", REMOTE_DIR)
    }

    fn new_with_prefix(
        server: bool,
        documents_dir: impl AsRef<Path>,
        user_id: impl AsRef<str>,
        prefix: impl AsRef<Path>,
    ) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(prefix);
        let logs_dir = documents_dir.join(LOGS_DIR);
        let identity_dir = documents_dir.join(IDENTITY_DIR);
        let audit_file = local_dir.join(AUDIT_FILE_NAME);
        let user_dir = local_dir.join(user_id.as_ref());

        let files_dir = user_dir.join(FILES_DIR);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        let device_file =
            user_dir.join(format!("{}.{}", DEVICE_FILE, VAULT_EXT));

        // Version 2 of the account storage backend (SQLite)
        let blobs_dir = documents_dir.join(BLOBS_DIR);
        let database_file = documents_dir.join(DATABASE_FILE);

        Self {
            server,
            user_id: user_id.as_ref().to_owned(),
            documents_dir,
            database_file,
            blobs_dir,
            logs_dir,

            identity_dir,
            local_dir,
            audit_file,
            user_dir,
            files_dir,
            vaults_dir,
            device_file,
        }
    }

    /// Whether these paths are for server-side storage.
    pub fn is_server(&self) -> bool {
        self.server
    }

    /// Clone of paths with an account identifier.
    pub fn with_account_id(&self, account_id: &AccountId) -> Self {
        if self.server {
            Self::new_with_prefix(
                true,
                self.documents_dir.clone(),
                account_id.to_string(),
                REMOTE_DIR,
            )
        } else {
            Self::new(&self.documents_dir, account_id.to_string())
        }
    }

    /// Ensure the local storage directory exists.
    ///
    /// If a user identifier is available this will
    /// also create some user-specific directories.
    pub async fn ensure(&self) -> Result<()> {
        // Version 1 needs to local/remote directory
        vfs::create_dir_all(&self.local_dir).await?;

        if !self.is_global() {
            // Version 1 file system - needs to be removed eventually
            vfs::create_dir_all(&self.user_dir).await?;
            vfs::create_dir_all(&self.files_dir).await?;
            vfs::create_dir_all(&self.vaults_dir).await?;
        }
        Ok(())
    }

    /// Ensure the local storage directory exists for version 2
    /// database storage.
    pub async fn ensure_db(&self) -> Result<()> {
        // Version 2 just needs the blobs directory
        vfs::create_dir_all(&self.blobs_dir).await?;
        if !self.is_global() {
            // Version 2 database backend needs a blobs folder
            vfs::create_dir_all(self.blobs_account_dir()).await?;
        }
        Ok(())
    }

    /// Determine if a database file exists.
    pub fn is_using_db(&self) -> bool {
        self.database_file().exists()
    }

    /// Try to determine if the account is ready to be used
    /// by checking for the presence of required files on disc.
    pub async fn is_usable(&self) -> Result<bool> {
        if self.is_global() {
            panic!("is_usable is not accessible for global paths");
        }

        let identity_vault = self.identity_vault();
        let identity_events = self.identity_events();
        let account_events = self.account_events();
        let device_events = self.device_events();

        Ok(vfs::try_exists(identity_vault).await?
            && vfs::try_exists(identity_events).await?
            && vfs::try_exists(account_events).await?
            && vfs::try_exists(device_events).await?)
    }

    /// Path to the database file for an account.
    ///
    /// # Panics
    ///
    /// If the paths are global.
    pub fn database_file(&self) -> &PathBuf {
        &self.database_file
    }

    /// External file blobs directory.
    pub fn blobs_dir(&self) -> &PathBuf {
        &self.blobs_dir
    }

    /// Expected location for the directory containing
    /// all the external file blobs for an account.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn blobs_account_dir(&self) -> PathBuf {
        if self.is_global() {
            panic!(
                "blobs account directory is not accessible for global paths"
            );
        }
        self.blobs_dir().join(self.user_id())
    }

    /// Expected location for the directory containing
    /// all the external files for a folder.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn blob_folder_location(&self, vault_id: &VaultId) -> PathBuf {
        self.blobs_account_dir().join(vault_id.to_string())
    }

    /// Expected location for an external file blob.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn blob_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: impl AsRef<str>,
    ) -> PathBuf {
        self.blob_folder_location(vault_id)
            .join(secret_id.to_string())
            .join(file_name.as_ref())
    }

    /// User identifier.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Top-level storage directory.
    pub fn documents_dir(&self) -> &PathBuf {
        &self.documents_dir
    }

    /// Determine if the paths are global.
    ///
    /// Paths are global when a user identifier
    /// is not available.
    pub fn is_global(&self) -> bool {
        self.user_id.is_empty()
    }

    /// Path to the identity vault directory.
    pub fn identity_dir(&self) -> &PathBuf {
        &self.identity_dir
    }

    /// Path to the local storage.
    pub fn local_dir(&self) -> &PathBuf {
        &self.local_dir
    }

    /// Path to the logs directory.
    pub fn logs_dir(&self) -> &PathBuf {
        &self.logs_dir
    }

    /// Path to the audit file.
    pub fn audit_file(&self) -> &PathBuf {
        &self.audit_file
    }

    /// Path to the file used to store global or
    /// account-level preferences.
    pub fn preferences_file(&self) -> PathBuf {
        let mut path = if self.is_global() {
            self.documents_dir().join(PREFERENCES_FILE)
        } else {
            self.user_dir().join(PREFERENCES_FILE)
        };
        path.set_extension(JSON_EXT);
        path
    }

    /// Path to the file used to store account-level system messages.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn system_messages_file(&self) -> PathBuf {
        if self.is_global() {
            panic!("system messages are not accessible for global paths");
        }
        let mut path = self.user_dir().join(SYSTEM_MESSAGES_FILE);
        path.set_extension(JSON_EXT);
        path
    }

    /// User specific storage directory.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn user_dir(&self) -> &PathBuf {
        if self.is_global() {
            panic!("user directory is not accessible for global paths");
        }
        &self.user_dir
    }

    /// User's files directory.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn files_dir(&self) -> &PathBuf {
        if self.is_global() {
            panic!("files directory is not accessible for global paths");
        }
        &self.files_dir
    }

    /// Expected location for the directory containing
    /// all the external files for a folder.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn file_folder_location(&self, vault_id: &VaultId) -> PathBuf {
        self.files_dir().join(vault_id.to_string())
    }

    /// Expected location for a file.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
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

    /// User's vaults storage directory.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn vaults_dir(&self) -> &PathBuf {
        if self.is_global() {
            panic!("vaults directory is not accessible for global paths");
        }
        &self.vaults_dir
    }

    /// User's device signing key vault file.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn device_file(&self) -> &PathBuf {
        if self.is_global() {
            panic!("devices file is not accessible for global paths");
        }
        &self.device_file
    }

    /// Path to the identity vault file for this user.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn identity_vault(&self) -> PathBuf {
        if self.is_global() {
            panic!("identity vault is not accessible for global paths");
        }
        let mut identity_vault_file = self.identity_dir.join(&self.user_id);
        identity_vault_file.set_extension(VAULT_EXT);
        identity_vault_file
    }

    /// Path to the identity events log for this user.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn identity_events(&self) -> PathBuf {
        let mut events_path = self.identity_vault();
        events_path.set_extension(EVENT_LOG_EXT);
        events_path
    }

    /// Path to a vault file from it's identifier.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn vault_path(&self, id: &VaultId) -> PathBuf {
        if self.is_global() {
            panic!("vault path is not accessible for global paths");
        }
        let mut vault_path = self.vaults_dir.join(id.to_string());
        vault_path.set_extension(VAULT_EXT);
        vault_path
    }

    /// Path to an event log file from it's identifier.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn event_log_path(&self, id: &VaultId) -> PathBuf {
        if self.is_global() {
            panic!("event log path is not accessible for global paths");
        }
        let mut vault_path = self.vaults_dir.join(id.to_string());
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Path to the user's account event log file.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn account_events(&self) -> PathBuf {
        if self.is_global() {
            panic!("account events are not accessible for global paths");
        }
        let mut vault_path = self.user_dir.join(ACCOUNT_EVENTS);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Path to the user's event log of device changes.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn device_events(&self) -> PathBuf {
        if self.is_global() {
            panic!("device events are not accessible for global paths");
        }
        let mut vault_path = self.user_dir.join(DEVICE_EVENTS);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Path to the user's event log of external file changes.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn file_events(&self) -> PathBuf {
        if self.is_global() {
            panic!("file events are not accessible for global paths");
        }
        let mut vault_path = self.user_dir.join(FILE_EVENTS);
        vault_path.set_extension(EVENT_LOG_EXT);
        vault_path
    }

    /// Path to the file used to store remote origins.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn remote_origins(&self) -> PathBuf {
        if self.is_global() {
            panic!("remote origins are not accessible for global paths");
        }
        let mut vault_path = self.user_dir.join(REMOTES_FILE);
        vault_path.set_extension(JSON_EXT);
        vault_path
    }

    /// Ensure the root directories exist for file system storage.
    pub async fn scaffold(data_dir: Option<PathBuf>) -> Result<()> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let paths = Self::new_global(data_dir);
        vfs::create_dir_all(paths.documents_dir()).await?;
        vfs::create_dir_all(paths.identity_dir()).await?;
        vfs::create_dir_all(paths.logs_dir()).await?;
        Ok(())
    }

    /// Ensure the root directories exist for database storage.
    pub async fn scaffold_db(data_dir: Option<PathBuf>) -> Result<()> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let paths = Self::new_global(data_dir);
        vfs::create_dir_all(paths.documents_dir()).await?;
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
}

#[cfg(target_os = "android")]
fn default_storage_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(""))
}

#[cfg(all(not(target_arch = "wasm32"), not(target_os = "android")))]
fn default_storage_dir() -> Result<PathBuf> {
    let strategy = choose_native_strategy(AppStrategyArgs {
        top_level_domain: "com".to_string(),
        author: APP_AUTHOR.to_string(),
        app_name: APP_NAME.to_string(),
    })
    .map_err(Box::from)?;

    #[cfg(not(windows))]
    {
        let mut path = strategy.data_dir();
        path.set_file_name(APP_AUTHOR);
        Ok(path)
    }
    #[cfg(windows)]
    {
        let mut path = strategy.cache_dir();
        path.pop();
        Ok(path)
    }
}

#[cfg(target_arch = "wasm32")]
fn default_storage_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("/"))
}
