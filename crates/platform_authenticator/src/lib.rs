//! Platform authenticator and keyring support for the
//! [Save Our Secrets SDK](https://saveoursecrets.com).
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;

pub mod keyring_password;
pub mod local_auth;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
