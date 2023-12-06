//! Error type for the client module.
#[cfg(feature = "client")]
use crate::client::{Origin, SyncError};
use http::StatusCode;
use serde_json::Value;
use sos_sdk::{
    commit::CommitHash,
    crypto::{AccessKey, SecureAccessKey},
    events::WriteEvent,
    vault::{Summary, VaultId},
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

    /// Error generated when an archive folder is not available.
    #[deprecated]
    #[error("archive folder does not exist")]
    NoArchive,

    /// Error generated when an open folder is expected.
    #[deprecated]
    #[error("no open folder")]
    NoOpenFolder,

    /// Error generated when secret data does not have an identifier
    /// but an existing secret is expected.
    #[deprecated]
    #[error("secret does not have an identifier")]
    NoSecretId,

    /// Error generated when a file secret is expected.
    #[deprecated]
    #[error("not a file secret")]
    NotFileContent,

    /// Error generated when attempting to archive a secret that
    /// is already archived.
    #[deprecated]
    #[error("cannot move to archive, already archived")]
    AlreadyArchived,

    /// Error generated when attempting to unarchive a secret that
    /// is not archived.
    #[deprecated]
    #[error("cannot unarchive, not archived")]
    NotArchived,

    /// Error generated when a path is not a directory.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when no default folder is available.
    #[deprecated]
    #[error("no default folder")]
    NoDefaultFolder,

    /// Error generated when a secret is not a contact secret.
    #[deprecated]
    #[cfg(feature = "contacts")]
    #[error("not a contact")]
    NotContact,

    /// Error generated when a contacts folder is not available.
    #[deprecated]
    #[cfg(feature = "contacts")]
    #[error("no contacts folder")]
    NoContactsFolder,

    /// Error generated when a PEM-encoded certificate is invalid.
    #[deprecated]
    #[error("invalid PEM encoding")]
    PemEncoding,

    /// Error generated when a provider is not valid.
    #[error("provider {0} is not valid")]
    InvalidProvider(String),

    /// Error generated when a file already exists.
    #[error("file {0} already exists")]
    FileExists(PathBuf),

    /*
    /// Error generated when unlocking a vault failed.
    #[error("failed to unlock vault")]
    VaultUnlockFail,
    */
    /// Error generated when an unexpected response code is received.
    #[error("unexpected response status code {0}")]
    ResponseCode(StatusCode),

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response {1} (code: {0})")]
    ResponseJson(StatusCode, Value),

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
        /// Commit hash of the local event log.
        local: (CommitHash, usize),
        /// Commit hash of the remote event log.
        remote: (CommitHash, usize),
        /// Events that can be applied after a pull.
        events: Vec<WriteEvent>,
    },

    /// Error generated when a conflict is detected that may be
    /// resolved by the user.
    #[error("conflict detected that may be resolvable")]
    Conflict {
        /// Summary of the vault that triggered the conflict.
        summary: Summary,
        /// Commit hash of the local event log.
        local: (CommitHash, usize),
        /// Commit hash of the remote event log.
        remote: (CommitHash, usize),
    },

    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

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

    /*
    /// Error generated attempting to make changes to the current
    /// vault but no vault is open.
    #[error("no vault is available, vault must be open")]
    NoOpenVault,

    /// Error generated when a secret could not be found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotFound(SecretId),
    */
    /// Error generated when account status could not be retrieved.
    #[error("could not fetch account status")]
    NoAccountStatus,

    /// Error generated when an event log buffer is expected.
    #[error("no event buffer returned when loading events")]
    NoEventBuffer,

    /// Error generated when a remote origin could not be found.
    #[error("origin '{0}' not found")]
    OriginNotFound(Origin),

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

    /// Error generated by the MPC library.
    #[error(transparent)]
    Mpc(#[from] mpc_protocol::Error),

    /// Error generated by the noise library.
    #[error(transparent)]
    Snow(#[from] mpc_protocol::snow::Error),

    /// Error generated sending a secure access key
    /// from a remote provider to the account storage.
    #[error(transparent)]
    MpscSecureAccessKey(
        #[from]
        tokio::sync::mpsc::error::SendError<(VaultId, SecureAccessKey)>,
    ),

    /// Error generated sending a access key
    /// from account storage to a remote provider.
    #[error(transparent)]
    MpscAccessKey(#[from] tokio::sync::mpsc::error::SendError<AccessKey>),

    /// Error generated sending a vault identifier
    /// from a remote provider to account storage.
    #[error(transparent)]
    MpscVaultId(#[from] tokio::sync::mpsc::error::SendError<VaultId>),
}

impl From<SyncError> for Error {
    fn from(value: SyncError) -> Self {
        match value {
            SyncError::One(e) => e,
            _ => unreachable!(),
        }
    }
}
