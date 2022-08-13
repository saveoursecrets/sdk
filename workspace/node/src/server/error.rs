//! Error type for the server.
use sos_core::address::AddressStr;
use std::path::PathBuf;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Errors generated by the server module.
#[derive(Debug, Error)]
pub enum Error {
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

    /// Error generated when a file stem is expected.
    #[error("file stem was expected")]
    NoFileStem,

    /// Error generated when no vaults could be found.
    #[error("no vaults found")]
    NoVaults,

    /// Error generated when an account does not exist.
    #[error("account {0} does not exist")]
    AccountNotExist(AddressStr),

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

    /// Error generated when a checksum does not match a WAL file.
    #[error("checksum mismatch validating WAL file")]
    WalValidateMismatch,

    /// Error generated failing for remove a vault.
    #[error("failed to remove in-memory vault, files still exist on disc")]
    VaultRemove,

    /// Error generated when a session does not exist.
    #[error("session does not exist")]
    NoSession,

    /// Error generated when a session identity signature does not 
    /// match the initial address.
    #[error("bad session identity signature")]
    BadSessionIdentity,

    /// Error generated when attempting to compute a shared secret
    /// before a session identity has been proven.
    #[error("session identity has not been proven")]
    NoSessionIdentity,

    /// Error generated when a session does not yet have a salt.
    #[error("session salt has not been set")]
    NoSessionSalt,

    /// Error generated when a session shared secret has not yet been
    /// created.
    #[error("session shared secret has not been set")]
    NoSessionSharedSecret,

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// Error generated when a header value is invalid.
    #[error(transparent)]
    HeaderValue(#[from] axum::http::header::InvalidHeaderValue),

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
    Ecdsa(#[from] k256::ecdsa::Error),

    /// Error generate by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generate by the UUID library.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generate by the elliptic curve library.
    #[error(transparent)]
    Elliptic(#[from] k256::elliptic_curve::Error),
}
