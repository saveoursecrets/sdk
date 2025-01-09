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
mod public_identity;

pub use identity::*;
pub use identity_folder::{DiscIdentityFolder, IdentityFolder};
pub use private_identity::PrivateIdentity;
pub use public_identity::{AccountRef, PublicIdentity};

pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
