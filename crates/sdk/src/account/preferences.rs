//! Preferences for each account.
//!
//! Preference are stored as a JSON map
//! of named keys to typed data similar to
//! the shared preferences provided by an operating
//! system library.
use crate::{
    identity::PublicIdentity, signer::ecdsa::Address, vfs, Error, Paths,
    Result,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

static CACHE: Lazy<Mutex<HashMap<Address, Arc<Mutex<Preferences>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Cache of preferences stored by account address.
pub struct CachedPreferences;

impl CachedPreferences {
    /// Initialize preferences for each referenced identity.
    pub async fn initialize(
        accounts: &[PublicIdentity],
        data_dir: Option<PathBuf>,
    ) -> Result<()> {
        for account in accounts {
            Self::new_account(account.address(), data_dir.clone()).await?;
        }
        Ok(())
    }

    /// Preferences for an account.
    pub async fn account_preferences(
        address: &Address,
    ) -> Option<Arc<Mutex<Preferences>>> {
        let cache = CACHE.lock().await;
        cache.get(address).map(Arc::clone)
    }

    /// Add a new account to the cached preferences.
    ///
    /// If a preferences file exists for an account it is loaded
    /// into memory otherwise empty preferences are used.
    pub async fn new_account(
        address: &Address,
        data_dir: Option<PathBuf>,
    ) -> Result<()> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let mut cache = CACHE.lock().await;
        let paths = Paths::new(&data_dir, address.to_string());
        let file = paths.preferences();
        let prefs = if vfs::try_exists(&file).await? {
            let mut prefs = Preferences::new(&paths);
            prefs.load().await?;
            prefs
        } else {
            Preferences::new(&paths)
        };
        cache.insert(address.clone(), Arc::new(Mutex::new(prefs)));
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

/// Preferences for an account.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Preferences {
    /// Preference values.
    #[serde(flatten)]
    values: HashMap<String, Preference>,
    /// Path to the file on disc.
    #[serde(skip)]
    path: PathBuf,
}

impl Preferences {
    /// Create new preferences using the given paths.
    ///
    /// # Panics
    ///
    /// If the given paths are global.
    ///
    pub fn new(paths: &Paths) -> Self {
        Self {
            path: paths.preferences(),
            values: Default::default(),
        }
    }

    /// Load the preferences stored on disc into memory.
    ///
    /// If the file does not exist this is a noop.
    pub async fn load(&mut self) -> Result<()> {
        if vfs::try_exists(&self.path).await? {
            let content = vfs::read(&self.path).await?;
            let prefs: Preferences = serde_json::from_slice(&content)?;
            self.values = prefs.values;
        }
        Ok(())
    }

    /// Number of preferences.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the preferences collection is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterator of the preferences.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Preference)> {
        self.values.iter()
    }

    /// Get a number preference.
    pub fn get_number(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>> {
        let result = self.values.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::Number(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeNumber(key.as_ref().to_owned()))
            }
        } else {
            Ok(None)
        }
    }

    /// Get a boolean preference.
    pub fn get_bool(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>> {
        let result = self.values.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::Bool(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeBool(key.as_ref().to_owned()))
            }
        } else {
            Ok(None)
        }
    }

    /// Get a string preference.
    pub fn get_string(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>> {
        let result = self.values.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::String(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeString(key.as_ref().to_owned()))
            }
        } else {
            Ok(None)
        }
    }

    /// Get a string list preference.
    pub fn get_string_list(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<&Preference>> {
        let result = self.values.get(key.as_ref());
        if let Some(res) = result.as_ref() {
            if matches!(res, Preference::StringList(_)) {
                Ok(result)
            } else {
                Err(Error::PreferenceTypeStringList(key.as_ref().to_owned()))
            }
        } else {
            Ok(None)
        }
    }

    /// Get a preference without checking the type.
    pub fn get_unchecked(&self, key: impl AsRef<str>) -> Option<&Preference> {
        self.values.get(key.as_ref())
    }

    /// Insert a preference.
    ///
    /// If the preference already exists it is overwritten.
    ///
    /// Changes are written to disc.
    pub async fn insert(
        &mut self,
        key: String,
        value: Preference,
    ) -> Result<()> {
        self.values.insert(key, value);
        self.save().await
    }

    /// Remove a preference.
    ///
    /// Changes are written to disc.
    pub async fn remove(
        &mut self,
        key: impl AsRef<str>,
    ) -> Result<Option<Preference>> {
        let pref = self.values.remove(key.as_ref());
        self.save().await?;
        Ok(pref)
    }

    /// Clear all preferences.
    ///
    /// Changes are written to disc.
    pub async fn clear(&mut self) -> Result<()> {
        self.values = Default::default();
        self.save().await
    }

    /// Save these preferences to disc.
    async fn save(&self) -> Result<()> {
        let buf = serde_json::to_vec_pretty(self)?;
        vfs::write(&self.path, buf).await?;
        Ok(())
    }
}
