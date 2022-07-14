use sos_core::{vault::Summary, CommitHash};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error("file {0} already exists")]
    FileExists(PathBuf),

    #[error("could not determine local data directory")]
    NoDataLocalDir,

    #[error("failed to unlock vault")]
    VaultUnlockFail,

    #[error("unexpected response status code {0}")]
    ResponseCode(u16),

    #[error("local and remote root hashes do not match; local = {0}, remote = {1}; you may need to pull or push to sync changes")]
    RootHashMismatch(CommitHash, CommitHash),

    #[error("server failed to send the expected commit proof headers")]
    ServerProof,

    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),

    #[error("conflict detected that may be resolvable")]
    Conflict {
        summary: Summary,
        local: (CommitHash, usize),
        remote: (CommitHash, usize),
    },

    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ToStr(#[from] reqwest::header::ToStrError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Keystore(#[from] web3_keystore::KeyStoreError),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    EventSource(#[from] reqwest_eventsource::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
}
