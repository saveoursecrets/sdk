use sos_core::{commit::CommitHash, VaultId};
use thiserror::Error;

/// Errors generated by the database library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a folder could not be found in the database.
    #[error("folder '{0}' not found in the database")]
    DatabaseFolderNotFound(VaultId),

    /// Error generated when a login folder is required.
    #[error("login folder not found for account id '{0}'")]
    NoLoginFolder(i64),

    /// Error generated when a target commit hash could not be found.
    #[error("commit '{0}' could not be found")]
    CommitNotFound(CommitHash),

    /// Error generated when replacing events in an event log
    /// does not compute the same root hash as the expected
    /// checkpoint.
    #[error("checkpoint verification failed, expected root hash '{checkpoint}' but computed '{computed}')")]
    CheckpointVerification {
        /// Checkpoint root hash.
        checkpoint: CommitHash,
        /// Computed root hash.
        computed: CommitHash,
    },

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated converting integers.
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),

    /// Errors generated by the UUID library.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the URL library.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Errors generated by refinery migration library.
    #[error(transparent)]
    Refinery(#[from] refinery::Error),

    /// Errors generated by the async sqlite library.
    #[error(transparent)]
    AsyncSqlite(#[from] async_sqlite::Error),

    /// Errors generated by the rusqlite library.
    #[error(transparent)]
    Rusqlite(#[from] async_sqlite::rusqlite::Error),

    #[cfg(feature = "system-messages")]
    /// Errors generated by the URN library.
    #[error(transparent)]
    Urn(#[from] urn::Error),
}
