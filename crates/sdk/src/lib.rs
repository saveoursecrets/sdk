#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! Software development kit for a
//! distributed encrypted database that can be used
//! to build password managers, cryptocurrency wallets
//! or other applications that require storing secrets
//! securely.
//!
//! A higher-level account management API is described in [sos_account::Account](https://docs.rs/sos-account/latest/sos_account/)
//! which is implemented by [LocalAccount](https://docs.rs/sos-account/latest/sos_account/). For a network aware
//! account use [NetworkAccount](https://docs.rs/sos-net/latest/sos_net/client/struct.NetworkAccount.html) in [sos-net](https://docs.rs/sos-net/latest/sos_net/).
//!
//! For lower-level access use the types in the [vault] module.
//!
//! # Features
//!
//! * `audit` Audit trail logs.
//! * `archive` Shared types for account backup archives.
//! * `contacts` Manage account contacts.
//! * `files` Store external encrypted files.
//! * `logs` Log file support.
//! * `migrate` Import and export unencrypted secrets.
//! * `search` In-memory search index.
//!

#[cfg(feature = "archive")]
pub mod archive;

#[cfg(feature = "audit")]
pub mod audit;
pub mod crypto;
mod date_time;
pub mod device;
pub mod encoding;
mod error;
pub mod events;
pub mod formats;
pub mod identity;
pub mod integrity;

#[cfg(feature = "logs")]
pub mod logs;

#[cfg(feature = "migrate")]
pub mod migrate;

pub mod passwd;
pub(crate) mod paths;
pub mod prelude;

#[doc(hidden)]
#[cfg(feature = "recovery")]
pub mod recovery;

#[cfg(feature = "search")]
pub mod search;

pub mod signer;
pub mod vault;

pub use date_time::UtcDateTime;
pub use encoding::{decode, encode};
pub use error::Error;
pub use paths::Paths;

// Re-exports
pub use age;
pub use argon2;
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

pub use sos_core::constants;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
