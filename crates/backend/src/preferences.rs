use crate::Error;
use async_trait::async_trait;
use sos_core::{AccountId, Paths, PublicIdentity};
use sos_database::{
    async_sqlite::Client, PreferenceProvider as DbPreferenceProvider,
};
use sos_filesystem::PreferenceProvider as FsPreferenceProvider;
use sos_preferences::{
    CachedPreferences, PreferenceManager, PreferenceStorageProvider,
    Preferences,
};
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use tokio::sync::Mutex;

static DB: OnceLock<Arc<PreferenceStorageProvider<Error>>> = OnceLock::new();
static FS: OnceLock<Arc<PreferenceStorageProvider<Error>>> = OnceLock::new();

/// Backend preferences.
pub struct BackendPreferences(CachedPreferences<Error>);

impl BackendPreferences {
    /// Create file system preferences from a data directory.
    pub fn new_fs_directory(
        data_dir: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let paths = Arc::new(Paths::new_global(data_dir));
        Ok(Self::new_fs(paths))
    }

    /// Create preferences using JSON files on disc.
    pub fn new_fs(paths: Arc<Paths>) -> Self {
        let provider = FS.get_or_init(|| {
            Arc::new(Box::new(FsPreferenceProvider::new(paths)))
        });
        Self(CachedPreferences::new(provider.clone()))
    }

    /// Create preferences using a database table.
    pub fn new_db(client: Client) -> Self {
        let provider = DB.get_or_init(|| {
            Arc::new(Box::new(DbPreferenceProvider::new(client)))
        });
        Self(CachedPreferences::new(provider.clone()))
    }
}

#[async_trait]
impl PreferenceManager for BackendPreferences {
    type Error = Error;

    async fn load_global_preferences(&mut self) -> Result<(), Self::Error> {
        self.0.load_global_preferences().await
    }

    async fn load_account_preferences(
        &self,
        accounts: &[PublicIdentity],
    ) -> Result<(), Self::Error> {
        self.0.load_account_preferences(accounts).await
    }

    fn global_preferences(&self) -> Arc<Mutex<Preferences<Self::Error>>> {
        self.0.global_preferences()
    }

    async fn account_preferences(
        &self,
        account_id: &AccountId,
    ) -> Option<Arc<Mutex<Preferences<Self::Error>>>> {
        self.0.account_preferences(account_id).await
    }

    async fn new_account(
        &self,
        account_id: &AccountId,
    ) -> Result<(), Self::Error> {
        self.0.new_account(account_id).await
    }
}
