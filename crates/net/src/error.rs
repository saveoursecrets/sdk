//! Error type for the client module.
use sos_core::Origin;
use sos_protocol::{transfer::CancelReason, AsConflict, ConflictError};
use sos_sdk::{prelude::ErrorExt, vault::VaultId};
use std::error::Error as StdError;
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the client module.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a path is not a directory.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when a file already exists.
    #[error("file {0} already exists")]
    FileExists(PathBuf),

    /// Error generated when a folder already exists.
    #[error("folder {0} already exists")]
    FolderExists(VaultId),

    /// Error generated when a return value is expected from a RPC call
    /// but the response did not have a result.
    #[error("method did not return a value")]
    NoReturnValue,

    /// Error generated when a remote origin could not be found.
    #[error("origin '{0}' not found")]
    OriginNotFound(Origin),

    /// Error generated attempting to revoke the current device.
    #[error("cannot revoke access to this device")]
    RevokeDeviceSelf,

    /// Error generated when failing to sync after revoking a device.
    #[error("failed to sync after revoking device, {0}")]
    RevokeDeviceSync(Box<Error>),

    /// Error generated force update of an account failed.
    #[error("failed to force update, {0}")]
    ForceUpdate(Box<Error>),

    /// Error generated trying to parse a device enrollment sharing URL.
    #[deprecated]
    #[error("invalid share url for device enrollment")]
    InvalidShareUrl,

    /// Error generated when a conflict is detected.
    #[error(transparent)]
    Conflict(#[from] ConflictError),

    /// Error generated parsing to an integer.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    /// Error generated by the io module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated attempting to convert from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Error generated by the storage library.
    #[error(transparent)]
    Storage(#[from] sos_client_storage::Error),

    /// Error generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Error generated by the account library.
    #[error(transparent)]
    Account(#[from] sos_account::Error),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated attempting to convert to a UTF-8 string.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Error generated converting an HTTP status code.
    #[error(transparent)]
    HttpStatus(#[from] http::status::InvalidStatusCode),

    /// Error generated when converting to a UUID.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated when parsing from hex.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Error generated by the wire protocol library.
    #[error(transparent)]
    Protocol(#[from] crate::protocol::Error),

    /// Error generated by the migrate library.
    #[error(transparent)]
    #[cfg(feature = "migrate")]
    Migrate(#[from] sos_migrate::Error),

    /// Error generated by network communication.
    #[error(transparent)]
    Network(#[from] sos_protocol::NetworkError),
}

impl ErrorExt for Error {
    fn is_secret_not_found(&self) -> bool {
        matches!(
            self,
            Error::Account(sos_account::Error::Storage(
                sos_client_storage::Error::SecretNotFound(_)
            ))
        )
    }

    fn is_permission_denied(&self) -> bool {
        matches!(self, Error::Sdk(crate::sdk::Error::PassphraseVerification))
    }
}

impl Error {
    /// Determine if this is a canceled error and
    /// whether the cancellation was triggered by the user.
    pub fn cancellation_reason(&self) -> Option<&CancelReason> {
        let source = source_error(self);
        if let Some(err) = source.downcast_ref::<Error>() {
            if let Error::Protocol(sos_protocol::Error::TransferCanceled(
                reason,
            )) = err
            {
                Some(reason)
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub(crate) fn source_error<'a>(
    error: &'a (dyn StdError + 'static),
) -> &'a (dyn StdError + 'static) {
    let mut source = error;
    while let Some(next_source) = source.source() {
        source = next_source;
    }
    source
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
