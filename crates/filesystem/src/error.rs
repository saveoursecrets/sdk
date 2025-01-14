use sos_core::commit::CommitHash;
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the filesystem library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0:#04x} at position {1} expecting {2}")]
    BadIdentity(u8, usize, String),

    /// Error generated when a buffer used to read identity bytes
    /// is not long enough.
    #[error("buffer passed for identity check is too short")]
    IdentityLength,

    /// Error generated when a target commit hash could not be found.
    #[error("commit '{0}' could not be found")]
    CommitNotFound(CommitHash),

    /// Error generated when replacing events in an event log
    /// does not compute the same root hash as the expected
    /// checkpoint.
    #[error("checkpoint verification failed, expected root hash '{checkpoint}' but computed '{computed}', snapshot rollback completed: '{rollback_completed}' (snapshot: '{snapshot:?}')")]
    CheckpointVerification {
        /// Checkpoint root hash.
        checkpoint: CommitHash,
        /// Computed root hash.
        computed: CommitHash,
        /// Snapshot path.
        snapshot: Option<PathBuf>,
        /// Whether a rollback completed.
        rollback_completed: bool,
    },

    /// Error generated trying to rewind an event log.
    #[error("rewind failed as pruned commits is greater than the length of the in-memory tree")]
    RewindLeavesLength,

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[cfg(feature = "preferences")]
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
