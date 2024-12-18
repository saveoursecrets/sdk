//! Global preferences and account-specific preferences
//! cached in-memory.
//!
//! Preference are stored as a JSON map
//! of named keys to typed data similar to
//! the shared preferences provided by an operating
//! system library.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sos_sdk::{
    constants::JSON_EXT, identity::PublicIdentity, signer::ecdsa::Address,
    vfs, Paths,
};
use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

/// File thats stores account-level preferences.
pub const PREFERENCES_FILE: &str = "preferences";

/// Path to the file used to store global or
/// account-level preferences.
fn preferences_path(paths: &Paths) -> PathBuf {
    let mut preferences_path = if paths.is_global() {
        paths.documents_dir().join(PREFERENCES_FILE)
    } else {
        paths.user_dir().join(PREFERENCES_FILE)
    };
    preferences_path.set_extension(JSON_EXT);
    preferences_path
}

/// Global preferences and account preferences loaded into memory.
pub struct CachedPreferences {
    data_dir: Option<PathBuf>,
    globals: Arc<Mutex<Preferences>>,
    accounts: Mutex<HashMap<Address, Arc<Mutex<Preferences>>>>,
}

impl CachedPreferences {
    /// Create new cached preferences.
    pub fn new(data_dir: Option<PathBuf>) -> Result<Self> {
        let global_dir = if let Some(data_dir) = data_dir.clone() {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new_global(&global_dir);
        Ok(Self {
            data_dir,
            globals: Arc::new(Mutex::new(Preferences::new(&paths))),
            accounts: Mutex::new(HashMap::new()),
        })
    }

    /// Load global preferences.
    pub async fn load_global_preferences(&mut self) -> Result<()> {
        let global_dir = if let Some(data_dir) = self.data_dir.clone() {
            data_dir
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new_global(&global_dir);
        let file = preferences_path(&paths);
        let globals = if vfs::try_exists(&file).await? {
            let mut prefs = Preferences::new(&paths);
            prefs.load().await?;
            prefs
        } else {
            Preferences::new(&paths)
        };
        self.globals = Arc::new(Mutex::new(globals));
        Ok(())
    }

    /// Load and initialize account preferences from disc.
    pub async fn load_account_preferences(
        &self,
        accounts: &[PublicIdentity],
    ) -> Result<()> {
        for account in accounts {
            self.new_account(account.address()).await?;
        }
        Ok(())
    }

    /// Global preferences for all accounts.
    pub fn global_preferences(&self) -> Arc<Mutex<Preferences>> {
        self.globals.clone()
    }

    /// Preferences for an account.
    pub async fn account_preferences(
        &self,
        address: &Address,
    ) -> Option<Arc<Mutex<Preferences>>> {
        let cache = self.accounts.lock().await;
        cache.get(address).map(Arc::clone)
    }

    /// Add a new account to the cached preferences.
    ///
    /// If a preferences file exists for an account it is loaded
    /// into memory otherwise empty preferences are used.
    pub async fn new_account(&self, address: &Address) -> Result<()> {
        let data_dir = if let Some(data_dir) = self.data_dir.clone() {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let mut cache = self.accounts.lock().await;
        let paths = Paths::new(&data_dir, address.to_string());
        let file = preferences_path(&paths);
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
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
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
            path: preferences_path(paths),
            values: Default::default(),
        }
    }

    /// Load the preferences stored on disc into memory.
    ///
    /// If the file does not exist this is a noop.
    pub async fn load(&mut self) -> Result<()> {
        if vfs::try_exists(&self.path).await? {
            let content = vfs::read_exclusive(&self.path).await?;
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
        vfs::write_exclusive(&self.path, buf).await?;
        Ok(())
    }
}
