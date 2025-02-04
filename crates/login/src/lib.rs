#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Identity folder protects delegated passwords and
//! is used to authenticate an account.

pub mod device;
mod error;
mod identity;
mod identity_folder;
mod private_identity;

pub use identity::*;
pub use identity_folder::IdentityFolder;
pub use private_identity::PrivateIdentity;

// DO NOT USE - backwards compatible re-exports
pub use sos_core::PublicIdentity;

pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
