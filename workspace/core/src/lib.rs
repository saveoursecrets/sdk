#![deny(missing_docs)]
//! Secret storage manager.

pub mod address;
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

pub mod secret;
pub mod signer;
mod timestamp;
pub mod vault;
pub mod wal;

#[cfg(test)]
pub mod test_utils;

pub use k256;
pub use serde_binary;
pub use serde_binary::binary_rw;
pub use web3_signature;

pub use crypto::algorithms::Algorithm;
pub use vault::{decode, encode};

pub use diceware::{generate_passphrase, generate_passphrase_words};
pub use error::Error;
pub use file_access::VaultFileAccess;
pub use file_identity::FileIdentity;
#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;
pub use gatekeeper::Gatekeeper;
pub use hash::CommitHash;
pub use timestamp::Timestamp;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
