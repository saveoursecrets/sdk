#![deny(missing_docs)]
//! Core library for the distributed, encrypted database.

use binary_stream::{
    BinaryReader, BinaryWriter, Decode, Encode, Endian, MemoryStream,
    SliceStream,
};

#[cfg(not(target_arch = "wasm32"))]
mod audit;

pub mod archive;
pub mod commit_tree;
pub mod constants;
pub mod crypto;
mod error;
pub mod events;
mod file_access;
mod file_identity;

#[cfg(not(target_arch = "wasm32"))]
mod file_locks;

mod gatekeeper;
mod hash;
pub mod identity;
pub mod iter;
pub mod passgen;
mod passwd;
mod patch;

pub mod rpc;
pub mod search;
pub mod secret;
pub mod signer;
mod timestamp;
pub mod vault;
pub mod wal;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(not(target_arch = "wasm32"))]
pub use audit::{AuditData, AuditEvent, AuditLogFile, AuditProvider};

pub use error::Error;
pub use file_access::VaultFileAccess;
pub use file_identity::FileIdentity;
#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;
pub use gatekeeper::Gatekeeper;
pub use hash::CommitHash;
pub use passgen::diceware::{generate_passphrase, generate_passphrase_words};
pub use passwd::ChangePassword;
#[cfg(not(target_arch = "wasm32"))]
pub use patch::PatchFile;
pub use patch::{Patch, PatchMemory, PatchProvider};
pub use timestamp::Timestamp;

/// Encode to a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    encode_endian(encodable, Endian::Big)
}

/// Decode from a binary buffer.
pub fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    decode_endian::<T>(buffer, Endian::Big)
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
