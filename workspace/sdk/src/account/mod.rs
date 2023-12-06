//! Create and manage local accounts.
mod account;
#[cfg(feature = "archive")]
pub mod archive;
mod builder;
#[cfg(feature = "contacts")]
pub mod contacts;
#[cfg(feature = "device")]
mod device;
#[cfg(feature = "files")]
pub mod files;
#[cfg(feature = "migrate")]
mod migrate;
mod paths;
#[cfg(feature = "search")]
pub mod search;

#[cfg(feature = "security-report")]
pub mod security_report;

pub use account::{
    Account, AccountData, AccountHandler, DetachedView, LocalAccount,
};
pub use builder::{AccountBuilder, NewAccount};
#[cfg(feature = "device")]
pub use device::DeviceSigner;
//pub use identity::{FolderKeys, Identity, PrivateIdentity, SecureKeys};
pub use paths::UserPaths;

/*
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Preferences for an account.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct AccountPreferences {
    /// Preference values.
    #[serde(flatten)]
    pub values: HashMap<String, Preference>,
}

/// Preference value.
#[derive(Clone, Serialize, Deserialize)]
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
*/
