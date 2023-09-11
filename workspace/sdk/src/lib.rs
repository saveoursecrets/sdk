#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! High-level software development kit for a
//! distributed encrypted database that can be used
//! to build password managers, cryptocurrency wallets
//! or other applications that require storing secrets
//! securely.

pub mod account;
pub mod commit;
pub mod constants;
pub mod crypto;
mod encoding;
mod error;
pub mod events;
pub mod formats;

#[cfg(feature = "keyring")]
mod keyring;

#[cfg(feature = "keyring")]
pub use self::keyring::{get_native_keyring, NativeKeyring};

pub mod passwd;
pub mod patch;
pub mod prelude;

#[cfg(feature = "recovery")]
pub mod recovery;

pub mod rpc;
pub mod search;
pub mod signer;
pub mod storage;
mod timestamp;
pub mod vault;
pub mod vfs;

#[cfg(all(not(doc), any(test, feature = "test-utils")))]
pub mod test_utils;

pub use encoding::{decode, encode};
pub use error::Error;
pub use timestamp::Timestamp;

// Re-exports
pub use age;
pub use hex;
pub use k256;
pub use mpc_protocol as mpc;
pub use pem;
pub use secrecy;
pub use sha2;
pub use sha3;
pub use time;
pub use totp_rs as totp;
pub use url;
pub use urn;
pub use uuid;
pub use vcard4;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
