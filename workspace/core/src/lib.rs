#![deny(missing_docs)]
//! Core library for the distributed, encrypted database.

use serde_binary::{binary_rw::Endian, Decode, Encode};

pub mod address;
mod audit;
pub mod commit_tree;
pub mod constants;
pub mod crypto;
mod diceware;
mod error;
pub mod events;
mod file_access;
mod file_identity;

#[cfg(not(target_arch = "wasm32"))]
mod file_locks;

mod gatekeeper;
mod hash;
pub mod iter;
mod passwd;
mod patch;

pub mod secret;
pub mod signer;
mod timestamp;
pub mod vault;
pub mod wal;

#[cfg(test)]
pub mod test_utils;

pub use audit::{AuditData, AuditEvent, AuditLogFile, AuditProvider};
pub use diceware::{generate_passphrase, generate_passphrase_words};
pub use error::Error;
pub use file_access::VaultFileAccess;
pub use file_identity::FileIdentity;
#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;
pub use gatekeeper::Gatekeeper;
pub use hash::CommitHash;
pub use passwd::ChangePassword;
pub use patch::{Patch, PatchFile};
pub use timestamp::Timestamp;

/// Encode into a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    Ok(serde_binary::encode(encodable, Endian::Big)?)
}

/// Decode from a binary buffer.
pub fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    Ok(serde_binary::decode::<T>(buffer, Endian::Big)?)
}

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
