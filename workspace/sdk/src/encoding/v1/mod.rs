mod commit;
mod crypto;
mod events;
mod patch;
mod rpc;
mod secret;
mod signer;
mod timestamp;
mod vault;

/// Version number for this encoding.
pub const VERSION: u16 = 1;

use crate::Result;
use binary_stream::{
    futures::{BinaryReader, BinaryWriter, Decode, Encode},
    Endian,
};
use futures::io::{AsyncSeek, AsyncSeekExt, BufReader, BufWriter, Cursor};
use std::io::SeekFrom;

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Get the length of this stream by seeking to the end
/// and then restoring the previous cursor position.
pub(crate) async fn stream_len<S: AsyncSeek + Unpin>(
    stream: &mut S,
) -> Result<u64> {
    let position = stream.stream_position().await?;
    let length = stream.seek(SeekFrom::End(0)).await?;
    stream.seek(SeekFrom::Start(position)).await?;
    Ok(length)
}

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    encode_endian(encodable, Endian::Little).await
}

/// Decode from a binary buffer.
pub async fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    decode_endian::<T>(buffer, Endian::Little).await
}

async fn encode_endian(
    encodable: &impl Encode,
    endian: Endian,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut stream = BufWriter::new(Cursor::new(&mut buffer));
    let mut writer = BinaryWriter::new(&mut stream, endian.into());
    encodable.encode(&mut writer).await?;
    writer.flush().await?;
    Ok(buffer)
}

async fn decode_endian<T: Decode + Default>(
    buffer: &[u8],
    endian: Endian,
) -> Result<T> {
    let mut stream = BufReader::new(Cursor::new(buffer));
    let mut reader = BinaryReader::new(&mut stream, endian.into());
    let mut decoded: T = T::default();
    decoded.decode(&mut reader).await?;
    Ok(decoded)
}
