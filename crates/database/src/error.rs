use sos_core::SecretId;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

/// Errors generated by the database library.
#[derive(Debug, Error)]
pub enum Error {
    /// Database file already exists.
    #[error("database '{0}' already exists")]
    DatabaseExists(PathBuf),

    /// Error generated attempting to access a vault that is not available.
    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),

    /// Error generated attempting to make changes to the current
    /// vault but no vault is open.
    #[error("no vault is available, vault must be open")]
    NoOpenVault,

    /// Error generated when a directory is expected.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when a file secret is expected.
    #[error("not a file secret")]
    NotFileContent,

    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Error generated when a search index is required.
    #[error("no search index")]
    NoSearchIndex,

    /// Error generated when no storage is configured.
    #[error(
        "account is empty, you may need to initialize the account or sign in"
    )]
    NoStorage,

    /// Error generated when a file encryption password is required.
    #[error("no file password")]
    NoFilePassword,

    /// Error generated when a secret could not be found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotFound(SecretId),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by refinery migration library.
    #[error(transparent)]
    Refinery(#[from] refinery::Error),

    /// Errors generated by the async sqlite library.
    #[error(transparent)]
    AsyncSqlite(#[from] async_sqlite::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the AGE library when encrypting.
    #[cfg(feature = "files")]
    #[error(transparent)]
    AgeEncrypt(#[from] age::EncryptError),

    /// Error generated by the AGE library when decrypting.
    #[cfg(feature = "files")]
    #[error(transparent)]
    AgeDecrypt(#[from] age::DecryptError),
}
