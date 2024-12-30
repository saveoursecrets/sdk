#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! High-level software development kit for a
//! distributed encrypted database that can be used
//! to build password managers, cryptocurrency wallets
//! or other applications that require storing secrets
//! securely.
//!
//! This library provides primitives for syncing when the `sync`
//! feature flag is enabled but does not perform any networking,
//! for networking support use the
//! [sos-net](https://docs.rs/sos-net/latest/sos_net/) crate.
//!
//! The high-level account management API is described in [account::Account]
//! which is implemented by [account::LocalAccount] for a network aware
//! account use [NetworkAccount](https://docs.rs/sos-net/latest/sos_net/client/struct.NetworkAccount.html) in [sos-net](https://docs.rs/sos-net/latest/sos_net/).
//!
//! For lower-level access use the types in the [vault] module.
//!
//! # Features
//!
//! Default features enable account management, audit trail,
//! search and backup archives. If you want to just use encrypted
//! vaults without the account management support disable `default-features`.
//!
//! * `account` Local account management.
//! * `audit` Audit trail logs.
//! * `files` Store external encrypted files.
//! * `recovery` Primitives for social recovery.
//! * `search` In-memory search index.
//!
//! The following features require that the `account` feature is enabled:
//!
//! * `archive` Create and restore from account backup archives.
//! * `contacts` Manage account contacts.
//! * `migrate` Import and export unencrypted secrets.
//!

#[cfg(all(not(feature = "account"), feature = "archive"))]
compile_error!("account feature must be enabled to use archive");

#[cfg(all(not(feature = "account"), feature = "contacts"))]
compile_error!("account feature must be enabled to use contacts");

#[cfg(all(not(feature = "account"), feature = "migrate"))]
compile_error!("account feature must be enabled to use migrate");

#[cfg(feature = "account")]
pub mod account;

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
pub mod storage;
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

pub use sos_core::commit;
pub use sos_core::constants;

#[cfg(feature = "clipboard")]
pub use serde_json_path as json_path;
#[cfg(feature = "clipboard")]
pub use xclipboard;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
