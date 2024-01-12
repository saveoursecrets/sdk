//! Error type for the client module.
#[cfg(feature = "client")]
use crate::client::{Origin, SyncError};
use http::StatusCode;
use serde_json::Value;
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

    /// Error generated when a single sync error is expected.
    #[error("single sync error expected")]
    SyncErrorOne,

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response status code {0}")]
    ResponseCode(StatusCode),

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response {1} (code: {0})")]
    ResponseJson(StatusCode, Value),

    /// Error generated when a return value is expected from a RPC call
    /// but the response did not have a result.
    #[error("method did not return a value")]
    NoReturnValue,

    /// Error generated when a remote origin could not be found.
    #[error("origin '{0}' not found")]
    OriginNotFound(Origin),

    /// Error generated when a websocket message is not binary.
    #[error("not binary message type on websocket")]
    NotBinaryWebsocketMessageType,

    /// Error generated when failing to fetch account from a remote
    /// during device enrollment.
    #[error("could not fetch account from remote '{0}'")]
    EnrollFetch(String),

    /// Error generated attempting to enroll a new device and
    /// the account already exists on the device.
    #[error("cannot enroll, account '{0}' already exists on this device")]
    EnrollAccountExists(String),

    /// Error generated when failing to sync after completing
    /// device enrollment.
    #[error("could not sync to '{0}' after device enrollment")]
    EnrollSync(String),

    /// Error generated when failing to sync after revoking a device.
    #[error("failed to sync after revoking device")]
    RevokeDeviceSync,

    /// Error generated by the RPC module.
    #[error(transparent)]
    Rpc(#[from] crate::rpc::Error),

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Error generated by the main node library.
    #[error(transparent)]
    Node(#[from] crate::Error),

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

    /// Error generated by the address library.
    #[error(transparent)]
    Address(#[from] web3_address::Error),

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

impl From<SyncError> for Error {
    fn from(value: SyncError) -> Self {
        match value {
            SyncError::One(e) => e,
            _ => unreachable!(),
        }
    }
}
