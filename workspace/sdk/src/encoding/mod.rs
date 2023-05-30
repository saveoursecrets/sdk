//! Binary encoding implementation.
pub mod v1;

pub use v1::*;

/*
use binary_stream::{BinaryReader, BinaryWriter, Decode, Encode, Endian};
use std::io::{Cursor, Seek, SeekFrom};
use crate::Result;

/// Get the length of this stream by seeking to the end
/// and then restoring the previous cursor position.
pub(crate) async fn async_stream_len<S: tokio::io::AsyncSeek + Unpin>(
    stream: &mut S,
) -> Result<u64> {
    use tokio::io::AsyncSeekExt;
    let position = stream.stream_position().await?;
    let length = stream.seek(SeekFrom::End(0)).await?;
    stream.seek(SeekFrom::Start(position)).await?;
    Ok(length)
}

/// Get the length of this stream by seeking to the end
/// and then restoring the previous cursor position.
pub(crate) fn stream_len<S: Seek>(stream: &mut S) -> Result<u64> {
    let position = stream.stream_position()?;
    let length = stream.seek(SeekFrom::End(0))?;
    stream.seek(SeekFrom::Start(position))?;
    Ok(length)
}

/// Encode to a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    encode_endian(encodable, Endian::Little)
}

/// Decode from a binary buffer.
pub fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    decode_endian::<T>(buffer, Endian::Little)
}

fn encode_endian(encodable: &impl Encode, endian: Endian) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut stream = Cursor::new(&mut buffer);
    let mut writer = BinaryWriter::new(&mut stream, endian);
    encodable.encode(&mut writer)?;
    Ok(buffer)
}

fn decode_endian<T: Decode + Default>(
    buffer: &[u8],
    endian: Endian,
) -> Result<T> {
    let mut stream = Cursor::new(buffer);
    let mut reader = BinaryReader::new(&mut stream, endian);
    let mut decoded: T = T::default();
    decoded.decode(&mut reader)?;
    Ok(decoded)
}

*/
