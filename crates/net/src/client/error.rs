//! Error type for the client module.
use crate::client::CancelReason;
use http::StatusCode;
use serde_json::Value;
#[cfg(feature = "client")]
use sos_sdk::sync::{Origin, SyncError};
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

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response status code {0}")]
    ResponseCode(StatusCode),

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response {1} (code: {0})")]
    ResponseJson(StatusCode, Value),

    /// Error generated when an unexpected content type is returend.
    #[error("unexpected content type {0}, expected: {1}")]
    ContentType(String, String),

    /// Error generated when a return value is expected from a RPC call
    /// but the response did not have a result.
    #[error("method did not return a value")]
    NoReturnValue,

    /// Error generated when a remote origin could not be found.
    #[error("origin '{0}' not found")]
    OriginNotFound(Origin),

    /// Error generated when an account is expected on a remote server
    /// but the account does not exist.
    #[error("account not found on server '{0}'")]
    NoServerAccount(Origin),

    /// Error generated attempting to patch devices but the account does
    /// not exist on the remote.
    #[error("cannot patch devices, account does not exist on remote")]
    NoAccountPatchDevices,

    /// Error generated when a websocket message is not binary.
    #[error("not binary message type on websocket")]
    NotBinaryWebsocketMessageType,

    /// Error generated attempting to revoke the current device.
    #[error("cannot revoke access to this device")]
    RevokeDeviceSelf,

    /// Error generated when failing to sync after revoking a device.
    #[error("failed to sync after revoking device, {0}")]
    RevokeDeviceSync(SyncError<Error>),

    /// Error generated force update of an account failed.
    #[error("failed to force update, {0}")]
    ForceUpdate(SyncError<Error>),

    /// Error generated trying to parse a device enrollment sharing URL.
    #[deprecated]
    #[error("invalid share url for device enrollment")]
    InvalidShareUrl,

    /// Error generated when a downloaded file checksum does not
    /// match the expected checksum.
    #[error("file download checksum mismatch; expected '{0}' but got '{1}'")]
    FileChecksumMismatch(String, String),

    /// Error generated when a file transfer is canceled.
    ///
    /// The boolean flag indicates whether the cancellation was
    /// triggered by the user.
    #[error("file transfer canceled")]
    TransferCanceled(CancelReason),

    /// Overflow error calculating the retry exponential factor.
    #[error("retry overflow")]
    RetryOverflow,

    /// Network retry was canceled possibly by the user.
    #[error("network retry was canceled")]
    RetryCanceled(CancelReason),

    /*
    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    */
    /// Error generated by the main net library.
    #[error(transparent)]
    Net(#[from] crate::Error),

    /// Error generated parsing to an integer.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    /// Error generated converting a header to a string.
    #[error(transparent)]
    ToStr(#[from] reqwest::header::ToStrError),

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
    Core(#[from] sos_sdk::Error),

    /// Error generated by the HTTP request library.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated attempting to convert to a UTF-8 string.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Error generated decoding a base58 string.
    #[error(transparent)]
    Base58Decode(#[from] bs58::decode::Error),

    /// Error generated converting an HTTP status code.
    #[error(transparent)]
    HttpStatus(#[from] http::status::InvalidStatusCode),

    /// Error generated by the websocket client.
    #[cfg(feature = "listen")]
    #[error(transparent)]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Error generated when converting to a UUID.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated when parsing from hex.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Error generated by the migrate library.
    #[error(transparent)]
    #[cfg(feature = "migrate")]
    Migrate(#[from] sos_sdk::migrate::Error),
}

impl Error {
    /// Determine if this is a canceled error and
    /// whether the cancellation was triggered by the user.
    pub fn cancellation_reason(&self) -> Option<&CancelReason> {
        let source = source_error(self);
        if let Some(err) = source.downcast_ref::<Error>() {
            if let Error::TransferCanceled(reason) = err {
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
