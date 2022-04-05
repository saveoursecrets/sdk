#![deny(missing_docs)]
//! Secret storage manager.

pub mod address;
pub mod crypto;
pub mod diceware;
pub mod error;
pub mod gatekeeper;
pub mod passphrase;
pub mod secret;
pub mod vault;

pub use crypto::algorithms::Algorithm;
pub use vault::{decode, encode};

pub use error::Error;

pub use uuid;

/// Result type for the core library.
pub type Result<T> = std::result::Result<T, Error>;
