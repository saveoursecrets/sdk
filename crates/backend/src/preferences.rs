use crate::{BackendTarget, Error};
use async_trait::async_trait;
use sos_core::{AccountId, PublicIdentity};
use sos_database::PreferenceProvider as DbPreferenceProvider;
use sos_filesystem::PreferenceProvider as FsPreferenceProvider;
use sos_preferences::{
    CachedPreferences, PreferenceManager, PreferenceStorageProvider,
    Preferences,
};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Backend preferences.
pub struct BackendPreferences(CachedPreferences<Error>);

impl BackendPreferences {
    /// Create new preferences.
    pub fn new(target: BackendTarget) -> Self {
        match target {
            BackendTarget::FileSystem(paths) => {
                let provider: PreferenceStorageProvider<Error> =
                    Box::new(FsPreferenceProvider::new(paths));
                Self(CachedPreferences::new(Arc::new(provider)))
            }
            BackendTarget::Database(_, client) => {
                let provider: PreferenceStorageProvider<Error> =
                    Box::new(DbPreferenceProvider::new(client));
                Self(CachedPreferences::new(Arc::new(provider)))
            }
        }
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
