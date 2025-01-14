//! Global preferences and account-specific preferences
//! cached in-memory.
//!
//! Preference are backed by a storage provider which may
//! be either a JSON document on disc or a database table
//! depending upon the backend implementation.
use crate::Error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sos_core::{AccountId, PublicIdentity};
use std::{collections::HashMap, fmt, sync::Arc};
use tokio::sync::Mutex;

/// Boxed storage provider.
pub type PreferenceStorageProvider<E> =
    Box<dyn PreferencesStorage<Error = E> + Send + 'static>;

/// Storage provider for account preferences.
#[async_trait]
pub trait PreferencesStorage {
    /// Error type.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + 'static;

    /// Load preferences from storage.
    async fn load_preferences(
        &self,
        account_id: Option<&AccountId>,
    ) -> Result<PreferenceMap, Self::Error>;

    /// Insert preference into storage.
    async fn insert_preference(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
        key: &str,
        pref: &Preference,
    ) -> Result<(), Self::Error>;

    /// Remove preference from storage.
    async fn remove_preference(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
        key: &str,
    ) -> Result<(), Self::Error>;

    /// Remove all preferences from storage.
    async fn clear_preferences(
        &self,
        account_id: Option<&AccountId>,
        preferences: &PreferenceMap,
    ) -> Result<(), Self::Error>;
}

/// Global preferences and account preferences loaded into memory.
pub struct CachedPreferences<'s, E>
where
    E: std::error::Error + std::fmt::Debug + From<Error> + Send + 'static,
{
    provider: &'s PreferenceStorageProvider<E>,
    globals: Arc<Mutex<Preferences<'s, E>>>,
    accounts: Mutex<HashMap<AccountId, Arc<Mutex<Preferences<'s, E>>>>>,
}

impl<'s, E> CachedPreferences<'s, E>
where
    E: std::error::Error + std::fmt::Debug + From<Error> + Send + 'static,
{
    /// Create new cached preferences.
    pub fn new(provider: &'s PreferenceStorageProvider<E>) -> Self {
        Self {
            globals: Arc::new(Mutex::new(Preferences::<E>::new(
                provider, None,
            ))),
            accounts: Mutex::new(HashMap::new()),
            provider,
        }
    }

    /// Load global preferences.
    pub async fn load_global_preferences(&mut self) -> Result<(), E> {
        let globals = self.globals.lock().await;
        globals.provider.load_preferences(None).await?;
        Ok(())
    }

    /// Load and initialize account preferences from disc.
    pub async fn load_account_preferences(
        &self,
        accounts: &[PublicIdentity],
    ) -> Result<(), E> {
        for account in accounts {
            self.new_account(account.account_id()).await?;
        }
        Ok(())
    }

    /// Global preferences for all accounts.
    pub fn global_preferences(&self) -> Arc<Mutex<Preferences<'s, E>>> {
        self.globals.clone()
    }

    /// Preferences for an account.
    pub async fn account_preferences(
        &'s self,
        account_id: &AccountId,
    ) -> Option<Arc<Mutex<Preferences<E>>>> {
        let cache = self.accounts.lock().await;
        cache.get(account_id).map(Arc::clone)
    }

    /// Add a new account to the cached preferences.
    ///
    /// If a preferences file exists for an account it is loaded
    /// into memory otherwise empty preferences are used.
    pub async fn new_account(&self, account_id: &AccountId) -> Result<(), E> {
        let mut prefs =
            Preferences::<E>::new(&self.provider, Some(*account_id));
        prefs.load().await?;

        let mut cache = self.accounts.lock().await;
        cache.insert(*account_id, Arc::new(Mutex::new(prefs)));
        Ok(())
    }
}

/// Preference value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Preference {
    /// Boolean value.
    Bool(bool),
    /// Number value.
    Number(f64),
    /// String value.
    String(String),
    /// List of strings.
    StringList(Vec<String>),
}

impl fmt::Display for Preference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(val) => write!(f, "{}", val),
            Self::Number(val) => write!(f, "{}", val),
            Self::String(val) => write!(f, "{}", val),
            Self::StringList(val) => {
                write!(f, "[")?;
                for (index, s) in val.iter().enumerate() {
                    write!(f, r#""{}""#, s)?;
                    if index < val.len() - 1 {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "]")
            }
        }
    }
}

impl From<bool> for Preference {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for Preference {
    fn from(value: f64) -> Self {
        Self::Number(value)
    }
}

impl From<i64> for Preference {
    fn from(value: i64) -> Self {
        Self::Number(value as f64)
    }
}

impl From<String> for Preference {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Vec<String>> for Preference {
    fn from(value: Vec<String>) -> Self {
        Self::StringList(value)
    }
}

/// Collection of preferences.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct PreferenceMap(HashMap<String, Preference>);

/// Preferences collection with a backing storage provider.
pub struct Preferences<'s, E>
where
    E: std::error::Error + std::fmt::Debug + From<Error> + Send + 'static,
{
    /// Account identifier.
    account_id: Option<AccountId>,
    /// Preference values.
    values: PreferenceMap,
    /// Storage provider.
    provider: &'s PreferenceStorageProvider<E>,
}

impl<'s, E> Preferences<'s, E>
where
    E: std::error::Error + std::fmt::Debug + From<Error> + Send + 'static,
{
    /// Create new preferences using the given storage provider.
    pub fn new(
        provider: &'s PreferenceStorageProvider<E>,
        account_id: Option<AccountId>,
    ) -> Self {
        Self {
            account_id,
            values: Default::default(),
            provider,
        }
    }

    /// Load the preferences from storage.
    pub async fn load(&mut self) -> Result<(), E> {
        self.values = self
            .provider
            .load_preferences(self.account_id.as_ref())
            .await?;
        Ok(())
    }

    /// Number of preferences.
    pub fn len(&self) -> usize {
        self.values.0.len()
    }

    /// Whether the preferences collection is empty.
    pub fn is_empty(&self) -> bool {
        self.values.0.is_empty()
    }

    /// Iterator of the preferences.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Preference)> {
        self.values.0.iter()
    }

    /// Get a number preference.
    pub fn get_number(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>, E> {
        let result = self.values.0.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::Number(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeNumber(key.as_ref().to_owned())
                    .into())
            }
        } else {
            Ok(None)
        }
    }

    /// Get a boolean preference.
    pub fn get_bool(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>, E> {
        let result = self.values.0.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::Bool(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeBool(key.as_ref().to_owned()).into())
            }
        } else {
            Ok(None)
        }
    }

    /// Get a string preference.
    pub fn get_string(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>, E> {
        let result = self.values.0.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::String(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeString(key.as_ref().to_owned())
                    .into())
            }
        } else {
            Ok(None)
        }
    }

    /// Get a string list preference.
    pub fn get_string_list(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>, E> {
        let result = self.values.0.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::StringList(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeStringList(key.as_ref().to_owned())
                    .into())
            }
        } else {
            Ok(None)
        }
    }

    /// Get a preference without checking the type.
    pub fn get_unchecked(&self, key: impl AsRef<str>) -> Option<&Preference> {
        self.values.0.get(key.as_ref())
    }

    /// Insert a preference.
    ///
    /// If the preference already exists it is overwritten.
    pub async fn insert(
        &mut self,
        key: String,
        value: Preference,
    ) -> Result<(), E> {
        self.values.0.insert(key.clone(), value.clone());
        self.provider
            .insert_preference(
                self.account_id.as_ref(),
                &self.values,
                &key,
                &value,
            )
            .await?;
        Ok(())
    }

    /// Remove a preference.
    pub async fn remove(
        &mut self,
        key: impl AsRef<str>,
    ) -> Result<Option<Preference>, E> {
        let pref = self.values.0.remove(key.as_ref());
        self.provider
            .remove_preference(
                self.account_id.as_ref(),
                &self.values,
                key.as_ref(),
            )
            .await?;
        Ok(pref)
    }

    /// Clear all preferences.
    pub async fn clear(&mut self) -> Result<(), E> {
        self.values = Default::default();
        self.provider
            .clear_preferences(self.account_id.as_ref(), &self.values)
            .await?;
        Ok(())
    }
}
