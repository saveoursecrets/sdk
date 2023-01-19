//! Error type for the client module.
use sos_core::{
    events::SyncEvent, secret::SecretId, vault::Summary, CommitHash,
};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

/// Errors generated by the client module.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Error generated when a path is not a directory.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when a provider is not valid.
    #[error("provider {0} is not valid")]
    InvalidProvider(String),

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

    /// Error generated when a conflict is detected where the local  
    /// is behind the remote.
    ///
    /// Pulling from remote and applying changes afterwards should resolve
    /// the conflict.
    #[error("conflict detected, pull required")]
    ConflictBehind {
        /// Summary of the vault that triggered the conflict.
        summary: Summary,
        /// Commit hash of the local WAL.
        local: (CommitHash, usize),
        /// Commit hash of the remote WAL.
        remote: (CommitHash, usize),
        /// Events that can be applied after a pull.
        events: Vec<SyncEvent<'static>>,
    },

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

    /// Error generated when a return value is expected from a RPC call
    /// but the response did not have a result.
    #[error("method did not return a value")]
    NoReturnValue,

    /// Error generated when a session has no been set.
    #[error("session not set, authentication is required")]
    NoSession,

    /// Error generated when a session has no been set.
    #[error("session is invalid, authentication is required")]
    InvalidSession,

    /// Error generated when a client receives an unauthorized response.
    #[error("not authorized, authentication is required")]
    NotAuthorized,

    /// Error generated attempting to make changes to the current
    /// vault but no vault is open.
    #[error("no vault is available, vault must be open")]
    NoOpenVault,

    /// Error generated when a secret could not be found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotFound(SecretId),

    /// Error generated when an archive signing key address
    /// does not match the address in the archive manifest.
    #[error("archive manifest address does not match identity signing key address")]
    ArchiveAddressMismatch,

    /// Error generated when an archive does not contain a default vault.
    #[error("archive does not contain a default vault")]
    NoArchiveDefaultVault,

    /// Error generated when an account does not exist.
    #[error("could not find account {0}")]
    NoAccount(String),

    /// Error generated when an archive is for an address that does
    /// not exist locally when we are expecting an archive to be imported
    /// in the context of an existing account.
    #[error("could not find account for archive address {0}")]
    NoArchiveAccount(String),

    /// Error generated attempting to restore an account from an archive
    /// whilst not authenticated and the address for the archive matches
    /// an account that already exists.
    #[error("account for archive address {0} already exists")]
    ArchiveAccountAlreadyExists(String),

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
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Error generated by the address library.
    #[error(transparent)]
    Address(#[from] web3_address::Error),
    /*
    /// Error generated by the websocket client.
    #[cfg(target_arch = "wasm32")]
    #[error(transparent)]
    WebSocket(#[from] ws_stream_wasm::WsErr),
    */
}
