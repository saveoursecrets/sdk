use sos_core::{AccountId, VaultId};
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the server storage library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a directory is expected.
    #[error("path '{0}' is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Error generated if we could not find a login folder for an account.
    #[error("could not find login folder for '{0}'")]
    NoLoginFolder(AccountId),

    /// Error generated when vault identifiers must match.
    #[error("identifier '{0}' does not match '{1}'")]
    VaultIdentifierMismatch(VaultId, VaultId),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the backend library.
    #[error(transparent)]
    Backend(#[from] sos_backend::Error),

    /// Errors generated by the filesystem library.
    #[error(transparent)]
    FileSystem(#[from] sos_filesystem::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated by the sync library.
    #[error(transparent)]
    Sync(#[from] sos_sync::Error),

    /// Errors generated by the backend storage.
    #[error(transparent)]
    BackendStorage(#[from] sos_backend::StorageError),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
