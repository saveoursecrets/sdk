//! Error type for the server library.
use thiserror::Error;

/// Errors generated by the networking library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated by the std::io module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /*
    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    */
    /// Error generated by the Base58 library.
    #[error(transparent)]
    Base58(#[from] bs58::encode::Error),
}
