//! Binary encoding implementation.
mod v1;

/// Version 1 encoding.
pub use v1::VERSION as VERSION1;

/// Current encoding version.
pub use v1::VERSION;

use crate::Result;
use binary_stream::{
    futures::{BinaryReader, Decodable, Encodable},
    Endian, Options,
};
use tokio::io::{AsyncRead, AsyncSeek};

/// Helper for mapping an encoding error.
pub fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Maximum buffer size allowed when encoding and decoding.
const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 16;

/// Standard encoding options.
pub fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(MAX_BUFFER_SIZE),
    }
}

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encodable) -> Result<Vec<u8>> {
    Ok(binary_stream::futures::encode(encodable, encoding_options()).await?)
}

/// Decode from a binary buffer.
pub async fn decode<T: Decodable + Default>(buffer: &[u8]) -> Result<T> {
    Ok(binary_stream::futures::decode(buffer, encoding_options()).await?)
}

/// Helper to decode a UUIDv4.
#[doc(hidden)]
pub async fn decode_uuid<R: AsyncRead + AsyncSeek + Unpin + Send>(
    reader: &mut BinaryReader<R>,
) -> std::result::Result<uuid::Uuid, std::io::Error> {
    let uuid: [u8; 16] = reader
        .read_bytes(16)
        .await?
        .as_slice()
        .try_into()
        .map_err(encoding_error)?;
    Ok(uuid::Uuid::from_bytes(uuid))
}
