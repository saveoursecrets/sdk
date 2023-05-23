#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! High-level software development kit (SDK) for a
//! distributed encrypted database that can be used
//! to build password managers, cryptocurrency wallets
//! or other applications that require storing secrets
//! securely.

use binary_stream::{BinaryReader, BinaryWriter, Decode, Encode, Endian};
use std::io::{SeekFrom, Seek, Cursor};

pub mod account;
#[cfg(not(target_arch = "wasm32"))]
pub mod audit;
pub mod commit;
pub mod constants;
pub mod crypto;
mod error;
pub mod events;
pub mod formats;
pub mod passwd;
pub mod patch;
pub mod rpc;
pub mod search;
pub mod signer;
pub mod storage;
mod timestamp;
pub mod vault;
pub mod vfs;
pub mod wal;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use error::Error;
pub use timestamp::Timestamp;

// Re-exports
pub use age;
pub use hex;
pub use k256;
pub use pem;
pub use secrecy;
pub use sha2;
pub use sha3;
pub use time;
pub use url;
pub use urn;
pub use uuid;
pub use vcard4;

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

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
