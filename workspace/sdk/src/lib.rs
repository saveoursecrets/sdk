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
pub mod encoding;
mod error;
pub mod events;
pub mod formats;

pub mod passwd;
pub mod prelude;

#[cfg(feature = "recovery")]
pub mod recovery;

pub mod signer;
mod timestamp;
pub mod vault;

#[cfg(all(not(doc), any(test, feature = "test-utils")))]
pub mod test_utils;

pub use encoding::{decode, encode};
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
pub use sos_vfs as vfs;
pub use time;
pub use totp_rs as totp;
pub use url;
pub use urn;
pub use uuid;
pub use vcard4;
pub use zxcvbn;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
