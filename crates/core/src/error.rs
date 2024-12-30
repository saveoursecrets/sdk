//! Errors generated by the core library.
use thiserror::Error;

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    /// Error generated when a commit tree is expected to have a last commit.
    #[error("commit tree does not have a last commit")]
    NoLastCommit,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated converting from hexadecimal.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}