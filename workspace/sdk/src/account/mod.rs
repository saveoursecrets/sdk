//! Create and manage local accounts.
mod account;
mod accounts_list;
#[cfg(feature = "archive")]
pub mod archive;
mod builder;
#[cfg(feature = "contacts")]
pub mod contacts;
#[cfg(feature = "device")]
mod device;
pub mod files;
mod identity;
mod local_storage;
mod paths;
pub mod search;

#[cfg(feature = "security-report")]
pub mod security_report;

pub use account::{
    AccessOptions, Account, AccountData, AccountHandler, DetachedView,
    LocalAccount,
};
pub use accounts_list::{AccountInfo, AccountRef, AccountsList};
pub use builder::{AccountBuilder, NewAccount};
#[cfg(feature = "device")]
pub use device::DeviceSigner;
pub use identity::{AccountStatus, AuthenticatedUser};
pub use local_storage::FolderStorage;
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
