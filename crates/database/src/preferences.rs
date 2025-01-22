use crate::{
    db::{AccountEntity, PreferenceEntity, PreferenceRow},
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
        let rows = self
            .client
            .conn_and_then(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    Ok::<_, Error>(
                        prefs.load_preferences(Some(account_row.row_id))?,
                    )
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    Ok::<_, Error>(prefs.load_preferences(None)?)
                }
            })
            .await?;

        let mut map: PreferenceMap = Default::default();
        for row in rows {
            let (key, pref) = row.try_into()?;
            map.inner_mut().insert(key, pref);
        }
        Ok(map)
    }

    async fn insert_preference(
        &self,
        account_id: Option<&AccountId>,
        key: &str,
        pref: &Preference,
    ) -> Result<(), Self::Error> {
        let account_id = account_id.cloned();
        let row = PreferenceRow::new_update(key, pref)?;
        Ok(self
            .client
            .conn(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs
                        .upsert_preference(Some(account_row.row_id), &row)?)
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs.upsert_preference(None, &row)?)
                }
            })
            .await
            .map_err(Error::from)?)
    }

    async fn remove_preference(
        &self,
        account_id: Option<&AccountId>,
        key: &str,
    ) -> Result<(), Self::Error> {
        let account_id = account_id.cloned();
        let key = key.to_owned();
        Ok(self
            .client
            .conn(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs
                        .delete_preference(Some(account_row.row_id), &key)?)
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs.delete_preference(None, &key)?)
                }
            })
            .await
            .map_err(Error::from)?)
    }

    async fn clear_preferences(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<(), Self::Error> {
        let account_id = account_id.cloned();
        Ok(self
            .client
            .conn(move |conn| match account_id {
                Some(account_id) => {
                    let account = AccountEntity::new(&conn);
                    let account_row = account.find_one(&account_id)?;
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs
                        .delete_all_preferences(Some(account_row.row_id))?)
                }
                None => {
                    let prefs = PreferenceEntity::new(&conn);
                    Ok(prefs.delete_all_preferences(None)?)
                }
            })
            .await
            .map_err(Error::from)?)
    }
}
