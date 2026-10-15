//! Identity folder protects delegated passwords and
//! is used to authenticate an account.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod delegated_access;
pub mod device;
mod error;
mod identity;
mod identity_folder;
mod private_identity;

pub use delegated_access::DelegatedAccess;
pub use identity::*;
pub use identity_folder::IdentityFolder;
pub use private_identity::PrivateIdentity;

// DO NOT USE - backwards compatible re-exports
pub use sos_core::PublicIdentity;

pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
