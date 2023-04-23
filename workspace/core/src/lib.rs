#![deny(missing_docs)]
//! Core library for the distributed, encrypted database.

use binary_stream::{
    BinaryReader, BinaryWriter, Decode, Encode, Endian, MemoryStream,
    SliceStream,
};

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
pub mod wal;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use error::Error;
pub use timestamp::Timestamp;

// Re-exports
pub use age;
pub use hex;
pub use k256;
pub use secrecy;
pub use sha2;
pub use sha3;
pub use time;
pub use url;
pub use urn;
pub use uuid;
pub use vcard4;

/// Encode to a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    encode_endian(encodable, Endian::Little)
}

/// Decode from a binary buffer.
pub fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    decode_endian::<T>(buffer, Endian::Little)
}

fn encode_endian(encodable: &impl Encode, endian: Endian) -> Result<Vec<u8>> {
    let mut stream = MemoryStream::new();
    let mut writer = BinaryWriter::new(&mut stream, endian);
    encodable.encode(&mut writer)?;
    Ok(stream.into())
}

fn decode_endian<T: Decode + Default>(
    buffer: &[u8],
    endian: Endian,
) -> Result<T> {
    let mut stream = SliceStream::new(buffer);
    let mut reader = BinaryReader::new(&mut stream, endian);
    let mut decoded: T = T::default();
    decoded.decode(&mut reader)?;
    Ok(decoded)
}

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
