//! Create and manage local accounts.
mod account;
pub mod archive;
mod builder;
#[cfg(feature = "contacts")]
pub mod contacts;
pub mod files;
mod identity;
mod local;
mod login;
mod password;
mod paths;
mod provider;
pub mod search;

#[cfg(feature = "security-report")]
pub mod security_report;

pub use account::{
    AccessOptions, Account, AccountData, AccountHandler, DetachedView,
    LocalAccount,
};
pub use builder::{AccountBuilder, NewAccount};
pub use identity::{AccountStatus, Identity};
pub use local::{AccountInfo, AccountRef, AccountsList};
pub use login::{AuthenticatedUser, DeviceSigner};
pub use paths::UserPaths;
pub use provider::FolderStorage;

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
