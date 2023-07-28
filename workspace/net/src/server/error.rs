//! Error type for the server.
use std::path::PathBuf;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use web3_address::ethereum::Address;

/// Errors generated by the server module.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when a path is not a directory.
    #[error("not a directory {0}")]
    NotDirectory(PathBuf),

    /// Error generated when a key file does not exist.
    #[error("key file '{0}' does not exist")]
    KeyNotFound(PathBuf),

    /// Error generated when a directory already exists.
    #[error("directory {0} already exists")]
    DirectoryExists(PathBuf),

    /// Error generated when a file already exists.
    #[error("file {0} already exists")]
    FileExists(PathBuf),

    /// Error generated when a file stem is expected.
    #[error("file stem was expected")]
    NoFileStem,

    /// Error generated when no vaults could be found.
    #[error("no vaults found")]
    NoVaults,

    /// Error generated when a commit proof is expected.
    #[error("no commit proof")]
    NoCommitProof,

    /// Error generated when an account does not exist.
    #[error("account {0} does not exist")]
    AccountNotExist(Address),

    /// Error generated when an vault does not exist.
    #[error("vault {0} does not exist")]
    VaultNotExist(Uuid),

    /// Error generated when a URL scheme is invalid.
    #[error("url scheme {0} is not supported")]
    InvalidUrlScheme(String),

    /// Error generated when a URL file path is invalid.
    #[error("url {0} is not a valid file path")]
    UrlFilePath(Url),

    /// Error generated when an audit file is already locked.
    #[error("audit log {0} is already open for writing")]
    AuditWouldBlock(PathBuf),

    /// Error generated when a checksum does not match a event log file.
    #[error("checksum mismatch validating event log file")]
    EventValidateMismatch,

    /// Error generated failing for remove a vault.
    #[error("failed to remove in-memory vault, files still exist on disc")]
    VaultRemove,

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the main library.
    #[error(transparent)]
    Node(#[from] crate::Error),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_sdk::Error),

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

    /// Error generated attempting to parse a socket address.
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    /// Error generate by the signature library.
    #[error(transparent)]
    Signature(#[from] web3_signature::SignatureError),

    /// Error generate by the ECDSA library.
    #[error(transparent)]
    Ecdsa(#[from] sos_sdk::k256::ecdsa::Error),

    /// Error generate by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generate by the UUID library.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated trying to decode from base58.
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),

    /// Error generated by the address library.
    #[error(transparent)]
    Address(#[from] web3_address::Error),

    /// Error generated by the MPC protocol library.
    #[error(transparent)]
    Mpc(#[from] sos_sdk::mpc::Error),
}
