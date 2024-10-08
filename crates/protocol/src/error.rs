//! Error type for the wire protocol.
use sos_sdk::time;
use thiserror::Error;

/// Errors generated by the wire protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// Reached EOF decoding a relay packet.
    #[error("relay packet end of file")]
    EndOfFile,

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the protobuf library when encoding.
    #[error(transparent)]
    ProtoBufEncode(#[from] prost::EncodeError),

    /// Error generated by the protobuf library when decoding.
    #[error(transparent)]
    ProtoBufDecode(#[from] prost::DecodeError),

    /// Error generated by the protobuf library when converting enums.
    #[error(transparent)]
    ProtoEnum(#[from] prost::UnknownEnumValue),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] crate::sdk::Error),

    /// Error generated by the merkle tree library.
    #[error(transparent)]
    Merkle(#[from] rs_merkle::Error),

    /// Error generated converting time types.
    #[error(transparent)]
    Time(#[from] time::error::ComponentRange),

    /// Error generated joining a task.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] crate::sdk::url::ParseError),
}
