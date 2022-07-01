#![deny(missing_docs)]
//! Secret storage manager.

pub mod address;
pub mod commit_tree;
pub mod crypto;
pub mod diceware;
pub mod error;
pub mod events;
pub mod file_access;
pub mod file_identity;

#[cfg(not(target_arch = "wasm32"))]
pub mod file_locks;

pub mod gatekeeper;
pub mod headers;
pub mod patch;

#[deprecated]
pub mod passphrase;

pub mod secret;
pub mod signer;
pub mod timestamp;
pub mod vault;
pub mod wal;

pub use k256;
pub use serde_binary;
pub use serde_binary::binary_rw;
pub use web3_signature;

pub use crypto::algorithms::Algorithm;
pub use vault::{decode, encode};

pub use error::Error;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
pub mod test_utils;
