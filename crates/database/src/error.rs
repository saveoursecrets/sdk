use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

/// Errors generated by the database library.
#[derive(Debug, Error)]
pub enum Error {
    /// Database file already exists.
    #[error("database '{0}' already exists")]
    DatabaseExists(PathBuf),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the audit library.
    #[error(transparent)]
    Audit(#[from] sos_audit::Error),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the login library.
    #[error(transparent)]
    Login(#[from] sos_login::Error),

    /// Errors generated by the filesystem library.
    #[error(transparent)]
    FileSystem(#[from] sos_filesystem::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "sqlite")]
    /// Errors generated by refinery migration library.
    #[error(transparent)]
    Refinery(#[from] refinery::Error),

    #[cfg(feature = "sqlite")]
    /// Errors generated by the async sqlite library.
    #[error(transparent)]
    AsyncSqlite(#[from] async_sqlite::Error),

    #[cfg(feature = "sqlite")]
    /// Errors generated by the rusqlite library.
    #[error(transparent)]
    Rusqlite(#[from] async_sqlite::rusqlite::Error),
}

/// Generic storage error shared between the client and server.
#[derive(Debug, Error)]
pub enum StorageError {
    #[cfg(feature = "client")]
    /// Error generated when no storage is configured.
    #[error(
        "account is empty, you may need to initialize the account or sign in"
    )]
    NoStorage,

    /// Error generated attempting to access a vault that is not available.
    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),
}
