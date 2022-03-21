//! Common traits.
use thiserror::Error;
use binary_rw::{BinaryReader, BinaryWriter};

/// Error thrown whilst encoding and decoding.
#[derive(Debug, Error)]
pub enum EncoderError {
    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0}")]
    BadIdentity(u8),

    /// Error generated when the kind of a secret is unknown.
    #[error("unknown secret kind {0}")]
    UnknownSecretKind(u8),

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated parsing UUIDs.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated from the binary reader / writer.
    #[error(transparent)]
    Binary(#[from] binary_rw::BinaryError),
}

/// Result type for encoding and decoding.
pub type EncoderResult<T> = std::result::Result<T, EncoderError>;

/// Trait for encoding to binary.
pub trait Encode {
    /// Encode self into the binary writer.
    fn encode(&self, writer: &mut BinaryWriter) -> EncoderResult<()>;
}

/// Trait for decoding from binary.
pub trait Decode {
    /// Decode from the binary reader into self.
    fn decode(&mut self, reader: &mut BinaryReader) -> EncoderResult<()>;
}
