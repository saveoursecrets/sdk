//! Account identity management.

mod device;
mod error;
mod identity;
mod identity_folder;
mod private_identity;
mod public_identity;

pub use identity::*;
pub use identity_folder::{
    DiscIdentityFolder, IdentityFolder, MemoryIdentityFolder,
};
pub use private_identity::PrivateIdentity;
pub use public_identity::{AccountRef, PublicIdentity};

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
