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
//!
//! This library provides primitives for syncing but does not
//! perform any networking, for networking support use
//! the [sos-net crate](https://docs.rs/sos-net/latest/sos_net/).
//!
//! # Features
//!
//! Default features enable account management, external files, search and
//! backup archives. If you want to just use encrypted vaults without
//! the account management support disable `default-features`.
//!
//! * `account` Support for local accounts.
//! * `recovery` Support for social recovery.
//!
//! The following features require that the `account` feature is enabled:
//!
//! * `archive` Support for creating and restoring from account backup archives.
//! * `contacts` Support for managing account contacts.
//! * `device` Support for device signing keys and device management.
//! * `files` Support for managing external encrypted files.
//! * `search` Support for in-memory account search index.
//! * `security-report` Support for generating a security report.
//!
//! Note the `files` feature affects the encoding of vaults so you should
//! not change this after writing encoded vaults to disc without having a
//! migration plan.

#[cfg(all(not(feature = "account"), feature = "archive"))]
compile_error!("account feature must be enabled to use archive");

#[cfg(all(not(feature = "account"), feature = "contacts"))]
compile_error!("account feature must be enabled to use contacts");

#[cfg(all(not(feature = "account"), feature = "device"))]
compile_error!("account feature must be enabled to use device");

#[cfg(all(not(feature = "account"), feature = "files"))]
compile_error!("account feature must be enabled to use files");

#[cfg(all(not(feature = "account"), feature = "migrate"))]
compile_error!("account feature must be enabled to use migrate");

#[cfg(all(not(feature = "account"), feature = "search"))]
compile_error!("account feature must be enabled to use search");

#[cfg(all(not(feature = "account"), feature = "security-report"))]
compile_error!("account feature must be enabled to use security-report");

#[cfg(feature = "account")]
pub mod account;
pub mod commit;
pub mod constants;
pub mod crypto;
pub mod encoding;
mod error;
pub mod events;
pub mod formats;

#[cfg(feature = "migrate")]
pub mod migrate;

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
