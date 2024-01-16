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
mod files;
#[cfg(feature = "migrate")]
mod migrate;
//#[cfg(feature = "search")]
//mod search;
#[cfg(feature = "sync")]
mod sync;

#[cfg(feature = "security-report")]
pub mod security_report;

pub use account::{
    Account, AccountData, DetachedView, LocalAccount, SecretChange,
    SecretDelete, SecretInsert, SecretMove,
};
pub use builder::{AccountBuilder, PrivateNewAccount};

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
