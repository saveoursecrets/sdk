use crate::{
    db::{AccountEntity, PreferenceEntity},
    Error,
};
use async_sqlite::Client;
use async_trait::async_trait;
use sos_core::AccountId;
use sos_preferences::{Preference, PreferenceMap, PreferencesStorage};

/// Store preferences in a database table.
pub struct PreferenceProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<sos_preferences::Error>
        + Send
        + Sync
        + 'static,
{
    client: Client,
    marker: std::marker::PhantomData<E>,
}

impl<E> PreferenceProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<sos_preferences::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new preferences database provider.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            marker: std::marker::PhantomData,
        }
    }

    /// Save these preferences to disc.
    async fn save(
        &self,
        account_id: Option<&AccountId>,
        values: &PreferenceMap,
    ) -> Result<(), E> {
        let account_id = account_id.cloned();
        let json_data = serde_json::to_string(values).map_err(Error::from)?;
        self.client
            .conn(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    prefs.insert_preferences(
                        Some(account_row.row_id),
                        json_data,
                    )?;
                    Ok(())
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    prefs.insert_preferences(None, json_data)?;
                    Ok(())
                }
            })
            .await
            .map_err(Error::from)?;
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
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn load_preferences(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<PreferenceMap, Self::Error> {
        let account_id = account_id.cloned();
        let json_data = self
            .client
            .conn(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs.load_preferences(Some(account_row.row_id))?)
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs.load_preferences(None)?)
                }
            })
            .await
            .map_err(Error::from)?;
        Ok(serde_json::from_str::<PreferenceMap>(&json_data)
            .map_err(Error::from)?)
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
