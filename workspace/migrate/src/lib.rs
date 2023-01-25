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

    /// Write the input secrets type to the specified vault.
    fn convert(
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> Result<Vault>;
}

pub mod export;
pub mod import;
