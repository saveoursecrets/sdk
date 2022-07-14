use sos_core::{secret::SecretRef, vault::Summary, CommitHash};
use std::path::PathBuf;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error("file {0} already exists")]
    FileExists(PathBuf),

    #[error("path {0} does not have a file name")]
    FileName(PathBuf),

    #[error("server url {0} is not HTTPS")]
    ServerHttps(Url),

    #[error("could not determine local data directory")]
    NoDataLocalDir,

    #[error("failed to create account, got status code {0}")]
    AccountCreate(u16),

    #[error(r#"vault "{0}" not found, run "vaults" to load the vault list"#)]
    VaultNotAvailable(SecretRef),

    #[error("failed to unlock vault")]
    VaultUnlockFail,

    #[error(r#"no vault selected, run "use" to select a vault"#)]
    NoVaultSelected,

    #[error(r#"secret "{0}" not found"#)]
    SecretNotAvailable(SecretRef),

    #[error("unexpected response status code {0}")]
    ResponseCode(u16),

    #[error("editor command did not exit successfully, status {0}")]
    EditorExit(i32),

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

    /// Error generated when a passphrase is not valid.
    #[error("passphrase is not valid")]
    InvalidPassphrase,

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
