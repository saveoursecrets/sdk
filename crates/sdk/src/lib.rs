#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! Software development kit for a
//! distributed, encrypted database that can be used
//! to build password managers, cryptocurrency wallets
//! or other applications that require storing secrets
//! securely.
//!
//! See the [Save Our Secrets](https://saveoursecrets.com) website
//! for more documentation and information.
//!
//! A higher-level account management API is described in [sos_account::Account](https://docs.rs/sos-account/latest/sos_account/trait.Account.html)
//! which is implemented by [sos_account::LocalAccount](https://docs.rs/sos-account/latest/sos_account/struct.LocalAccount.html). For a network aware
//! account with sync capability use [sos_net::NetworkAccount](https://docs.rs/sos-net/latest/sos_net/struct.NetworkAccount.html).
//!
//! For lower-level access use the types in the [vault] module.
//!
//! # Features
//!
//! * `contacts` Manage account contacts.
//! * `files` Store external encrypted files.
//!

pub mod device;
pub mod events;
pub mod prelude;

pub use sos_core::Paths;
pub use sos_core::{decode, encode};

// Deprecated re-exports for backwards compatibility
// DO NOT USE - some will be removed in the future
pub use sos_core::constants;
pub use sos_core::crypto;
pub use sos_core::UtcDateTime;
pub use sos_login as identity;
pub use sos_signer as signer;
pub use sos_vault as vault;
pub use sos_vfs as vfs;
