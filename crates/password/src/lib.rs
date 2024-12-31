//! Password generation and helpers for the
//! [Save Our Secrets](https://saveoursecrets.com) SDK.

pub mod diceware;
mod error;
pub mod generator;
mod memorable;

pub use error::Error;

/// Default cryptographically secure RNG.
pub(crate) fn csprng() -> impl rand::CryptoRng + rand::Rng {
    rand::rngs::OsRng
}

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
