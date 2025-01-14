use crate::Error;
use async_trait::async_trait;
use sos_core::{AccountId, Paths};
use sos_preferences::{Preference, PreferenceMap, PreferencesStorage};
use sos_vfs as vfs;
use std::{path::PathBuf, sync::Arc};

/// Store preferences in a file as JSON.
pub struct PreferenceProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<sos_preferences::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    paths: Arc<Paths>,
    marker: std::marker::PhantomData<E>,
}

impl<E> PreferenceProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<sos_preferences::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new prefernces file provider.
    pub fn new(paths: Arc<Paths>) -> Self {
        Self {
            paths,
            marker: std::marker::PhantomData,
        }
    }

    fn file_path(&self, account_id: Option<&AccountId>) -> PathBuf {
        let base = self.paths.documents_dir();
        let paths = if let Some(account_id) = account_id {
            Paths::new(base, account_id.to_string())
        } else {
            Paths::new_global(base)
        };
        paths.preferences_file().to_owned()
    }

    /// Save these preferences to disc.
    async fn save(
        &self,
        account_id: Option<&AccountId>,
        values: &PreferenceMap,
    ) -> Result<(), E> {
        let path = self.file_path(account_id);
        let buf = serde_json::to_vec_pretty(values).map_err(Error::from)?;
        vfs::write_exclusive(&path, buf).await?;
        Ok(())
    }
}

#[async_trait]
impl<E> PreferencesStorage for PreferenceProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<sos_preferences::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn load_preferences(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<PreferenceMap, Self::Error> {
        let path = self.file_path(account_id);
        let prefs = if vfs::try_exists(&path).await? {
            let content = vfs::read_exclusive(&path).await?;
            serde_json::from_slice::<PreferenceMap>(&content)
                .map_err(Error::from)?
        } else {
            Default::default()
        };
        Ok(prefs)
    }

    async fn insert_preference(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
        _key: &str,
        _pref: &Preference,
    ) -> Result<(), Self::Error> {
        Ok(self.save(account_id, preferences).await?)
    }

    async fn remove_preference(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
        _key: &str,
    ) -> Result<(), Self::Error> {
        Ok(self.save(account_id, preferences).await?)
    }

    async fn clear_preferences(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
    ) -> Result<(), Self::Error> {
        Ok(self.save(account_id, preferences).await?)
    }
}
