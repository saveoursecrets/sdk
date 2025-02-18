use sos_protocol::{AsConflict, ConflictError};
use thiserror::Error;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated by the password library.
    #[error(transparent)]
    Password(#[from] sos_password::Error),

    /// Error generated by the login library.
    #[error(transparent)]
    Login(#[from] sos_login::Error),

    /// Error generated by the backend library.
    #[error(transparent)]
    Backend(#[from] sos_backend::Error),

    /// Errors generated by the sync library.
    #[error(transparent)]
    Sync(#[from] sos_sync::Error),

    /// Errors generated by the storage library.
    #[error(transparent)]
    Storage(#[from] sos_client_storage::Error),

    /// Error generated by the backend storage.
    #[error(transparent)]
    BackendStorage(#[from] sos_backend::StorageError),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Errors generated by the account library.
    #[error(transparent)]
    Account(#[from] sos_account::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated by the remote sync library.
    #[error(transparent)]
    RemoteSync(#[from] sos_remote_sync::Error),

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
