//! Binary encoding implementation.
pub mod v1;

pub use v1::*;

use crate::Result;
use binary_stream::{
    futures::{BinaryReader, BinaryWriter, Decodable, Encodable},
    Endian, Options,
};
use futures::io::{
    AsyncRead, AsyncSeek, AsyncSeekExt, AsyncWrite, BufReader, BufWriter,
    Cursor,
};
use std::io::SeekFrom;

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

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

/// Encode to a stream.
pub async fn encode_stream<S>(
    encodable: &impl Encodable,
    stream: &mut S,
) -> Result<()>
where
    S: AsyncWrite + AsyncSeek + Send + Sync + Unpin,
{
    Ok(binary_stream::futures::encode_stream(
        encodable,
        stream,
        encoding_options(),
    )
    .await?)
}

/// Decode from a stream.
pub async fn decode_stream<
    T: Decodable + Default,
    S: AsyncRead + AsyncSeek + Send + Sync + Unpin,
>(
    stream: &mut S,
) -> Result<T> {
    Ok(
        binary_stream::futures::decode_stream(stream, encoding_options())
            .await?,
    )
}
