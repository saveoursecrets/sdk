//! Error type for the networking library.
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

    /// Error generated by the core library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Error generate by the ECDSA library.
    #[error(transparent)]
    Ecdsa(#[from] sos_sdk::k256::ecdsa::Error),

    /// Error generate by the elliptic curve library.
    #[error(transparent)]
    Elliptic(#[from] sos_sdk::k256::elliptic_curve::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the Base58 library.
    #[error(transparent)]
    Base58(#[from] bs58::encode::Error),

    /// Error generated by the protobuf library when encoding.
    #[error(transparent)]
    ProtoBufEncode(#[from] prost::EncodeError),

    /// Error generated by the protobuf library when decoding.
    #[error(transparent)]
    ProtoBufDecode(#[from] prost::DecodeError),
}
