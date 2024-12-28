use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the database library.
#[derive(Debug, Error)]
pub enum Error {
    /// Database file already exists.
    #[error("database '{0}' already exists")]
    DatabaseExists(PathBuf),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by refinery migration library.
    #[error(transparent)]
    Refinery(#[from] refinery::Error),

    /// Errors generated by the async sqlite library.
    #[error(transparent)]
    AsyncSqlite(#[from] async_sqlite::Error),
}
