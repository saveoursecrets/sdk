#![deny(missing_docs)]
//! Library to export secrets unencrypted for migration
//! or to import unencrypted data.
//!
//! Used to move between different software providers.

use secrecy::SecretString;
use sos_core::vault::Vault;

mod error;

pub use error::Error;

/// Result type for the migration library.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for implementations that can convert data
/// from a third-party provider.
pub trait Convert {
    /// Input type for the conversion.
    type Input;

    /// Convert the input type to vault.
    fn convert(source: Self::Input, password: SecretString) -> Vault;
}

pub mod export;
pub mod import;
