use thiserror::Error;

/// Errors generated by the library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when attempting to append audit
    /// events without any providers configured.
    #[error("no audit trail providers configured")]
    AuditProvidersNotConfigured,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Errors generated by the filesystem library.
    #[error(transparent)]
    FileSystem(#[from] sos_filesystem::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "preferences")]
    /// Errors generated by the preferences library.
    #[error(transparent)]
    Preferences(#[from] sos_preferences::Error),

    #[cfg(feature = "system-messages")]
    /// Errors generated by the system messages library.
    #[error(transparent)]
    SystemMessages(#[from] sos_system_messages::Error),
}
