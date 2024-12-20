use sos_protocol::{AsConflict, ConflictError};
use sos_sdk::prelude::{Address, VaultId};
use std::path::PathBuf;
use thiserror::Error;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Errors generated converting file system notify events.
    #[cfg(any(feature = "extension-helper-server"))]
    #[error(transparent)]
    FileNotifyEvent(#[from] FileEventError),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated when a URI is invalid.
    #[error(transparent)]
    HttpUri(#[from] http::uri::InvalidUri),

    /// Error generated by the HTTP library.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// Error generated by the HTTP library.
    #[error(transparent)]
    StatusCode(#[from] http::status::InvalidStatusCode),

    /// Errors generated by the hyper library.
    #[cfg(any(feature = "extension-helper-server"))]
    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    /// Errors generated by the file system notification library.
    #[cfg(any(feature = "extension-helper-server"))]
    #[error(transparent)]
    Notify(#[from] notify::Error),

    /// Errors generated from network responses.
    #[error(transparent)]
    Network(#[from] sos_protocol::NetworkError),

    /// Errors generated on conflict.
    #[error(transparent)]
    Conflict(#[from] sos_protocol::ConflictError),
}

impl AsConflict for Error {
    fn is_conflict(&self) -> bool {
        matches!(self, Error::Conflict(_))
    }

    fn is_hard_conflict(&self) -> bool {
        matches!(self, Error::Conflict(ConflictError::Hard))
    }

    fn take_conflict(self) -> Option<ConflictError> {
        match self {
            Self::Conflict(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(any(feature = "extension-helper-server"))]
/// Error type converting from file system notify events.
#[derive(Error, Debug)]
pub enum FileEventError {
    /// Error generated when a file system event does not have a path.
    #[error("no path available for file system event")]
    NoEventPath,

    /// Error generated when a file system event path does not have a stem.
    #[error("no file stem for event path {0:?}")]
    EventPathStem(PathBuf),

    /// Error generated when a file system event does not have a path.
    #[error("no account for {0}")]
    NoAccount(Address),

    /// Error generated when a file system event does not have a path.
    #[error("no account for {0}")]
    NoFolder(VaultId),
}
