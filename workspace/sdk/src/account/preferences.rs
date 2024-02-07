//! Preferences for each account.
//!
//! Preference are stored as a JSON map
//! of named keys to typed data similar to
//! the shared preferences provided by an operating
//! system library.
use crate::{
    identity::PublicIdentity, signer::ecdsa::Address, vfs, Paths, Result,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};
use tokio::sync::Mutex;

static CACHE: Lazy<Mutex<HashMap<Address, Preferences>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// In-memory cache of preferences stored by account address.
pub struct CachedPreferences;

impl CachedPreferences {
    /// Initialize preferences for each referenced identity address.
    ///
    /// If a preferences file exists for an account it is loaded
    /// into memory otherwise empty preferences are used.
    pub async fn initialize(
        accounts: &[PublicIdentity],
        data_dir: Option<PathBuf>,
    ) -> Result<()> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let mut cache = CACHE.lock().await;
        for account in accounts {
            let paths = Paths::new(&data_dir, account.address().to_string());
            let file = paths.preferences();
            let prefs = if file.exists() {
                let mut prefs = Preferences::new(&paths);
                prefs.load().await?;
                prefs
            } else {
                Preferences::new(&paths)
            };
            cache.insert(account.address().clone(), prefs);
        }
        Ok(())
    }

    /// Load the preferences for an account.
    pub async fn load(address: &Address) -> Preferences {
        let cache = CACHE.lock().await;
        if let Some(prefs) = cache.get(address) {
            prefs.clone()
        } else {
            Default::default()
        }
    }

    /// Get a preference for an account.
    pub async fn get(
        address: &Address,
        key: impl AsRef<str>,
    ) -> Result<Option<Preference>> {
        let cache = CACHE.lock().await;
        if let Some(prefs) = cache.get(address) {
            if let Some(value) = prefs.get(&key) {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Set a preference for an account.
    pub async fn set(
        address: &Address,
        key: String,
        value: Preference,
    ) -> Result<()> {
        let mut cache = CACHE.lock().await;
        let prefs = cache.entry(*address).or_default();
        prefs.insert(key, value).await?;
        Ok(())
    }

    /// Remove a preference for an account.
    pub async fn remove(
        address: &Address,
        key: impl AsRef<str>,
    ) -> Result<Option<Preference>> {
        let mut cache = CACHE.lock().await;
        let prefs = cache.entry(*address).or_default();
        prefs.remove(key).await
    }

    /// Clear all preferences for an account.
    pub async fn clear(address: &Address) -> Result<()> {
        let mut cache = CACHE.lock().await;
        if let Some(mut prefs) = cache.remove(address) {
            prefs.clear().await?;
        }
        Ok(())
    }
}

/// Preference value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Preference {
    /// Boolean value.
    Bool(bool),
    /// Float value.
    Double(f64),
    /// Integer value.
    Int(i64),
    /// String value.
    String(String),
    /// List of strings.
    StringList(Vec<String>),
}

impl From<bool> for Preference {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for Preference {
    fn from(value: f64) -> Self {
        Self::Double(value)
    }
}

impl From<i64> for Preference {
    fn from(value: i64) -> Self {
        Self::Int(value)
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
    pub values: HashMap<String, Preference>,
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
    pub async fn load(&mut self) -> Result<()> {
        let content = vfs::read(&self.path).await?;
        let prefs: Preferences = serde_json::from_slice(&content)?;
        self.values = prefs.values;
        Ok(())
    }

    /// Iterator of the preferences.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Preference)> {
        self.values.iter()
    }

    /// Get a preference.
    pub fn get(&self, key: impl AsRef<str>) -> Option<&Preference> {
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
