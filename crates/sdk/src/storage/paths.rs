//! File system paths for application level folders
//! and user-specific account folders.
use crate::Result;
#[cfg(feature = "audit")]
use async_once_cell::OnceCell;

#[cfg(not(target_arch = "wasm32"))]
use etcetera::{
    app_strategy::choose_native_strategy, AppStrategy, AppStrategyArgs,
};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use file_guard::{try_lock, FileGuard, Lock};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    future::Future,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use crate::{
    constants::{
        ACCOUNT_EVENTS, APP_AUTHOR, APP_LOCK_FILE, APP_NAME, AUDIT_FILE_NAME,
        DEVICE_EVENTS, DEVICE_FILE, EVENT_LOG_EXT, FILES_DIR, FILE_EVENTS,
        IDENTITY_DIR, JSON_EXT, LOCAL_DIR, LOCK_FILE, LOGS_DIR, PENDING_DIR,
        REMOTES_FILE, REMOTE_DIR, VAULTS_DIR, VAULT_EXT,
    },
    vault::{secret::SecretId, VaultId},
    vfs,
};

#[cfg(feature = "audit")]
use tokio::sync::Mutex;

#[cfg(feature = "audit")]
use crate::audit::{AuditEvent, AuditLogFile, AuditProvider};

// const APP_INFO: AppInfo = AppInfo {
//     name: APP_NAME,
//     author: APP_AUTHOR,
// };

static DATA_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

#[cfg(feature = "audit")]
static AUDIT_LOG: OnceCell<Mutex<AuditLogFile>> = OnceCell::new();

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
    /// File for local audit logs.
    audit_file: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// User file storage.
    files_dir: PathBuf,
    /// User vault storage.
    vaults_dir: PathBuf,
    /// Pending folders dir.
    pending_dir: PathBuf,
    /// User devices storage.
    device_file: PathBuf,
}

impl Paths {
    /// Create new paths for a client.
    pub fn new(
        documents_dir: impl AsRef<Path>,
        user_id: impl AsRef<str>,
    ) -> Self {
        Self::new_with_prefix(documents_dir, user_id, LOCAL_DIR)
    }

    /// Create new paths for a server.
    pub fn new_server(
        documents_dir: impl AsRef<Path>,
        user_id: impl AsRef<str>,
    ) -> Self {
        Self::new_with_prefix(documents_dir, user_id, REMOTE_DIR)
    }

    /// Create new paths for a client with an empty user identifier.
    ///
    /// Used to get application level paths when a user identifier
    /// is not available.
    pub fn new_global(documents_dir: impl AsRef<Path>) -> Self {
        Self::new(documents_dir, "")
    }

    /// Create new paths for a client with an empty user identifier.
    ///
    /// Used to get application level paths when a user identifier
    /// is not available.
    pub fn new_global_server(documents_dir: impl AsRef<Path>) -> Self {
        Self::new_server(documents_dir, "")
    }

    fn new_with_prefix(
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
        let pending_dir = user_dir.join(PENDING_DIR);
        let device_file =
            user_dir.join(format!("{}.{}", DEVICE_FILE, VAULT_EXT));
        Self {
            user_id: user_id.as_ref().to_owned(),
            documents_dir,
            identity_dir,
            local_dir,
            logs_dir,
            audit_file,
            user_dir,
            files_dir,
            vaults_dir,
            pending_dir,
            device_file,
        }
    }

    /// Ensure the local storage directory exists.
    ///
    /// If a user identifier is available this will
    /// also create some user-specific directories.
    pub async fn ensure(&self) -> Result<()> {
        vfs::create_dir_all(&self.local_dir).await?;
        if !self.is_global() {
            vfs::create_dir_all(&self.user_dir).await?;
            vfs::create_dir_all(&self.files_dir).await?;
            vfs::create_dir_all(&self.vaults_dir).await?;
            vfs::create_dir_all(&self.pending_dir).await?;
        }
        Ok(())
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

    /// Path to a pending vault file from it's identifier.
    ///
    /// # Panics
    ///
    /// If this set of paths are global (no user identifier).
    pub fn pending_vault_path(&self, id: &VaultId) -> PathBuf {
        if self.is_global() {
            panic!("pending vault path is not accessible for global paths");
        }
        let mut vault_path = self.pending_dir.join(id.to_string());
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

    /// Ensure the root directories exist.
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
    #[cfg(feature = "audit")]
    pub async fn append_audit_events(
        &self,
        events: Vec<AuditEvent>,
    ) -> Result<()> {
        let log_file = AUDIT_LOG
            .get_or_init(async move {
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

    /// Attempt to acquire an account lock.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) async fn acquire_account_lock<F>(
        &self,
        on_message: impl Fn() -> F,
    ) -> Result<FileLock>
    where
        F: Future<Output = Result<()>>,
    {
        if self.is_global() {
            panic!("account lock is not accessible for global paths");
        }
        let lock_path = self.user_dir.join(LOCK_FILE);
        let mut lock = FileLock::new(&lock_path)?;
        lock.acquire(on_message).await?;
        Ok(lock)
    }

    /// Attempt to acquire an app lock.
    #[doc(hidden)]
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn acquire_app_lock(&self) -> Result<Option<FileLock>> {
        let lock_path = self.documents_dir.join(APP_LOCK_FILE);
        let mut lock = FileLock::new(&lock_path)?;
        Ok(match lock.try_acquire() {
            Ok(_) => Some(lock),
            _ => None,
        })
    }

    /// Query if an app lock is active.
    #[doc(hidden)]
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn has_app_lock(&self) -> Result<bool> {
        let lock_path = self.documents_dir.join(APP_LOCK_FILE);
        let lock = FileLock::new(&lock_path)?;
        Ok(lock.is_lock_active()?)
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

/// Exclusive file lock.
///
/// Used to prevent multiple applications from accessing
/// the same account simultaneously which could lead to
/// data corruption.
#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub struct FileLock {
    file: Arc<File>,
    #[allow(dead_code)]
    guard: Option<FileGuard<Arc<File>>>,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl FileLock {
    /// New file lock.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            file: Arc::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path.as_ref())?,
            ),
            guard: None,
        })
    }

    /// Determine if the file lock is being held by any process.
    pub fn is_lock_active(&self) -> Result<bool> {
        Ok(match try_lock(self.file.clone(), Lock::Exclusive, 0, 1) {
            Ok(_) => false,
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => true,
                _ => return Err(e.into()),
            },
        })
    }

    /// Determine if this file lock has acquired the lock.
    pub fn is_acquired(&self) -> bool {
        self.guard.is_some()
    }

    /// Try to acquire the file lock for a path.
    pub fn try_acquire(&mut self) -> Result<()> {
        match try_lock(self.file.clone(), Lock::Exclusive, 0, 1) {
            Ok(guard) => {
                self.guard = Some(guard);
                return Ok(());
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Try to acquire a file lock for a path, waiting until the
    /// lock becomes available.
    pub async fn acquire<F>(
        &mut self,
        on_message: impl Fn() -> F,
    ) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        let mut message_printed = false;

        loop {
            match try_lock(self.file.clone(), Lock::Exclusive, 0, 1) {
                Ok(guard) => {
                    self.guard = Some(guard);
                    return Ok(());
                }
                Err(e) => match e.kind() {
                    ErrorKind::WouldBlock => {
                        if !message_printed {
                            on_message().await?;
                            message_printed = true;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(
                            50,
                        ));
                        continue;
                    }
                    _ => return Err(e.into()),
                },
            }
        }
    }
}
