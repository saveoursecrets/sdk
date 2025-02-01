use sos_core::AccountId;
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated creating and importing backup archives,
#[derive(Debug, Error)]
pub enum Error {
    /// Archive file already exists.
    #[error("archive file '{0}' already exists")]
    ArchiveFileExists(PathBuf),

    /// Archive file does not exist.
    #[error("archive file '{0}' does not exist")]
    ArchiveFileNotExists(PathBuf),

    /// Error generated when an archive does not contain a
    /// valid manifest file.
    #[error("archive '{0}' manifest does not exist or is invalid")]
    InvalidArchiveManifest(PathBuf),

    /// Error generated when an archive does not contain the
    /// database file.
    #[error("archive '{0}' is missing the database '{1}'")]
    NoDatabaseFile(PathBuf, String),

    /// Error generated attempting to import an account that
    /// already exists in the target database.
    #[error("import failed, account '{0}' does not exist in source db")]
    ImportSourceNotExists(AccountId),

    /// Error generated attempting to import an account that
    /// already exists in the target database.
    #[error("import failed, account '{0}' already exists in target db")]
    ImportTargetExists(AccountId),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] crate::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the async sqlite library.
    #[error(transparent)]
    AsyncSqlite(#[from] async_sqlite::Error),

    /// Errors generated by the rusqlite library.
    #[error(transparent)]
    Rusqlite(#[from] async_sqlite::rusqlite::Error),

    /// Errors generated by refinery migration library.
    #[error(transparent)]
    Refinery(#[from] refinery::Error),

    /// Error generated by the ZIP library.
    #[error(transparent)]
    Zip(#[from] async_zip::error::ZipError),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),
}
