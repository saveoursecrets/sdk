//! Binary encoding implementation.
pub mod v1;

pub use v1::*;

const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 16;

use crate::Result;
use binary_stream::{
    futures::{BinaryReader, BinaryWriter, Decode, Encode},
    Endian, Options,
};
use futures::io::{AsyncSeek, AsyncSeekExt, BufReader, BufWriter, Cursor};
use std::io::SeekFrom;

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Standard encoding options.
pub fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(MAX_BUFFER_SIZE),
    }
}

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    encode_options(encodable, encoding_options()).await
}

/// Decode from a binary buffer.
pub async fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    decode_options::<T>(buffer, encoding_options()).await
}

async fn encode_options(
    encodable: &impl Encode,
    options: Options,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut stream = BufWriter::new(Cursor::new(&mut buffer));
    let mut writer = BinaryWriter::new(&mut stream, options);
    encodable.encode(&mut writer).await?;
    writer.flush().await?;
    Ok(buffer)
}

async fn decode_options<T: Decode + Default>(
    buffer: &[u8],
    options: Options,
) -> Result<T> {
    let mut stream = BufReader::new(Cursor::new(buffer));
    let mut reader = BinaryReader::new(&mut stream, options);
    let mut decoded: T = T::default();
    decoded.decode(&mut reader).await?;
    Ok(decoded)
}
