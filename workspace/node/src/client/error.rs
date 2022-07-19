//! Error type for the client module.
use sos_core::{vault::Summary, CommitHash};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

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

    /// Error generated when a local data directory could not be determined.
    #[error("could not determine local data directory")]
    NoDataLocalDir,

    /// Error generated when unlocking a vault failed.
    #[error("failed to unlock vault")]
    VaultUnlockFail,

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response status code {0}")]
    ResponseCode(u16),

    /// Error generated when root commit hashes do not match.
    #[error("local and remote root hashes do not match; local = {0}, remote = {1}; you may need to pull or push to sync changes")]
    RootHashMismatch(CommitHash, CommitHash),

    /// Error generated if a server failed to send the expected
    /// commit proof header.
    #[error("server failed to send the expected commit proof header")]
    ServerProof,

    /// Error generated attempting to access a vault that is not available.
    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),

    /// Error generated when a conflict is detected that may be
    /// resolved by the user.
    #[error("conflict detected that may be resolvable")]
    Conflict {
        /// Summary of the vault that triggered the conflict.
        summary: Summary,
        /// Commit hash of the local WAL.
        local: (CommitHash, usize),
        /// Commit hash of the remote WAL.
        remote: (CommitHash, usize),
    },

    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    /// Error generated attempting to take a snapshot when snapshots are disabled.
    #[error("snapshots must be enabled")]
    SnapshotsNotEnabled,

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

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

    /// Error generated by the keystore library.
    #[error(transparent)]
    Keystore(#[from] web3_keystore::KeyStoreError),

    /// Error generated attempting to convert from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated by the HTTP request library.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated by the event source library.
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    EventSource(#[from] reqwest_eventsource::Error),

    /// Error generated attempting to convert to a UTF-8 string.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Error generated decoding a base58 string.
    #[error(transparent)]
    Base58Decode(#[from] bs58::decode::Error),

    /// Error generated converting an HTTP status code.
    #[error(transparent)]
    HttpStatus(#[from] http::status::InvalidStatusCode),
}
