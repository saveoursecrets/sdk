//! Preferences for each account are a 
//! map of named keys to typed data similar to 
//! the shared preferences provided by an operating 
//! system library.
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
