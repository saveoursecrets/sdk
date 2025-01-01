use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a directory is expected.
    #[error("path '{0}' is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated by the sync library.
    #[error(transparent)]
    Sync(#[from] sos_sync::Error),

    /// Errors generated by the database storage.
    #[error(transparent)]
    DatabaseStorage(#[from] sos_database::StorageError),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
