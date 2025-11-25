use crate::{write_exclusive, Error};
use async_fd_lock::LockRead;
use async_trait::async_trait;
use sos_core::{AccountId, Paths};
use sos_preferences::{Preference, PreferenceMap, PreferencesStorage};
use sos_vfs::{self as vfs, File};
use std::{path::PathBuf, sync::Arc};
use tokio::io::AsyncReadExt;

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
    /// Create a new preferences file provider.
    pub fn new(paths: Arc<Paths>) -> Self {
        Self {
            paths,
            marker: std::marker::PhantomData,
        }
    }

    fn file_path(&self, account_id: Option<&AccountId>) -> PathBuf {
        let base = self.paths.documents_dir();
        let paths = if let Some(account_id) = account_id {
            Paths::new_client(base).with_account_id(account_id)
        } else {
            Paths::new_client(base)
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
        write_exclusive(&path, buf).await?;
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
            let file = File::open(&path).await?;
            let mut guard = file.lock_read().await.map_err(|e| e.error)?;
            let mut content = Vec::new();
            guard.read_to_end(&mut content).await?;
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
        key: &str,
        pref: &Preference,
    ) -> Result<(), Self::Error> {
        let mut prefs = self.load_preferences(account_id).await?;
        prefs.insert(key.to_owned(), pref.clone());
        Ok(self.save(account_id, &prefs).await?)
    }

    async fn remove_preference(
        &self,
        account_id: Option<&AccountId>,
        key: &str,
    ) -> Result<(), Self::Error> {
        let mut prefs = self.load_preferences(account_id).await?;
        prefs.remove(key);
        Ok(self.save(account_id, &prefs).await?)
    }

    async fn clear_preferences(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<(), Self::Error> {
        Ok(self.save(account_id, &Default::default()).await?)
    }
}
