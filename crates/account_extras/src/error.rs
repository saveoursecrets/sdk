use thiserror::Error;

/// Error type for the account extras library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a preference is not a number.
    #[cfg(feature = "preferences")]
    #[error("expecting integer preference for '{0}'")]
    PreferenceTypeNumber(String),

    /// Error generated when a preference is not a boolean.
    #[cfg(feature = "preferences")]
    #[error("expecting boolean preference for '{0}'")]
    PreferenceTypeBool(String),

    /// Error generated when a preference is not a string.
    #[cfg(feature = "preferences")]
    #[error("expecting string preference for '{0}'")]
    PreferenceTypeString(String),

    /// Error generated when a preference is not a string list.
    #[cfg(feature = "preferences")]
    #[error("expecting string list preference for '{0}'")]
    PreferenceTypeStringList(String),

    /// Error generated when a system message is not found.
    #[cfg(feature = "system-messages")]
    #[error("no system message for key '{0}'")]
    NoSysMessage(String),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the database storage.
    #[error(transparent)]
    DatabaseStorage(#[from] sos_database::StorageError),
}
