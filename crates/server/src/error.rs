//! Error type for the server.
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::{json, Value};
use sos_protocol::{
    sdk::signer::ecdsa::Address, Error as ProtocolError, Merge, MergeError,
};
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the server module.
#[derive(Debug, Error)]
pub enum Error {
    /// Generic error message.
    #[error("{0}")]
    Message(String),

    /// HTTP status code.
    #[error("{0}")]
    Status(StatusCode),

    /// Status code with JSON response.
    #[error("{0} {1}")]
    Json(StatusCode, Value),

    /// Unauthorized error.
    #[error("unauthorized, may need to retry the protocol handshake")]
    Unauthorized,

    /// Bad request error.
    #[error("bad request")]
    BadRequest,

    /// Forbidden access.
    #[error("forbidden")]
    Forbidden,

    /// Conflict.
    #[error("conflict")]
    Conflict,

    /// Error generated when an RPC method is not supported.
    #[error("unknown rpc method '{0}'")]
    RpcUnknownMethod(String),

    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when a path is not a directory.
    #[error("not a directory {0}")]
    NotDirectory(PathBuf),

    /// Error generated when a directory already exists.
    #[error("directory {0} already exists")]
    DirectoryExists(PathBuf),

    /// Error generated when a file already exists.
    #[error("file {0} already exists")]
    FileExists(PathBuf),

    /// Error generated when an account is required.
    #[error("account '{0}' does not exist")]
    NoAccount(Address),

    /// Error generated when an account should not already exist.
    #[error("account '{0}' already exists")]
    AccountExists(Address),

    /// Error generated when an uploaded file checksum does not
    /// match the expected checksum.
    #[error("file upload checksum mismatch; expected '{0}' but got '{1}'")]
    FileChecksumMismatch(String, String),

    /// Error generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Error generated by the storage library.
    #[error(transparent)]
    Storage(#[from] sos_storage::server::Error),

    /// Error generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// Error generated when a header value is invalid.
    #[error(transparent)]
    HeaderValue(#[from] axum::http::header::InvalidHeaderValue),

    /// Error generated by the web server library.
    #[error(transparent)]
    WebServer(#[from] axum::Error),

    /// Error generated by the io module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated deserializing from TOML.
    #[error(transparent)]
    TomlDeser(#[from] toml::de::Error),

    /// Error generated serializing to TOML.
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),

    /// Error generated attempting to parse a socket address.
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    /// Error generate by the ECDSA library.
    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),

    /// Error generate by the JSON library.
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    /// Error generate by the UUID library.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated trying to decode from base58.
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),

    /// Error generated by the HTTP library.
    #[error(transparent)]
    Http(#[from] axum::http::Error),
}

impl Error {
    /// Status code for the error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Status(status) => *status,
            Self::Json(status, _) => *status,
            Self::NoAccount(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Protocol(ProtocolError::Database(
                sos_database::Error::CacheNotAvailable(_),
            )) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the body for the error response.
    pub fn body(self) -> Value {
        match self {
            Self::Status(status) => {
                let message =
                    status.canonical_reason().unwrap_or("unknown reason");
                let status: u16 = status.into();
                json!({ "code": status, "message": message })
            }
            Self::Json(status, value) => match status {
                StatusCode::OK => value,
                _ => {
                    let status: u16 = status.into();
                    json!({ "code": status, "message": value })
                }
            },
            _ => {
                let status: u16 = self.status().into();
                let message = self.to_string();
                json!({ "code": status, "message": message })
            }
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response<Body> {
        let status = self.status();
        let body = self.body();
        (status, Json(body)).into_response()
    }
}

impl<T> From<MergeError<T>> for Error
where
    T: Merge,
{
    fn from(value: MergeError<T>) -> Self {
        Self::Message(value.err.to_string())
    }
}
