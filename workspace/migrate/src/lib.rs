#![deny(missing_docs)]
//! Migration import and export that exposes secrets
//! unencrypted.
//!
//! Used to move from or to another service provider or
//! software application.

use sos_core::vault::Vault;
use secrecy::SecretString;

mod error;

pub use error::Error;

/// Result type for the migration library.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for implementations that can convert data 
/// from a third-party provider.
pub trait Convert {
    type Input;
    
    /// Convert the input type to vault.
    fn convert(source: Self::Input, password: SecretString) -> Vault;
}

pub mod export;
pub mod import;
