//! Password generation and helpers for the
//! [Save Our Secrets](https://saveoursecrets.com) SDK.

pub mod diceware;
mod error;
pub mod generator;
mod memorable;

pub use error::Error;
pub use memorable::memorable_password;

pub use zxcvbn;

/// Default cryptographically secure RNG.
pub(crate) fn csprng() -> impl rand::CryptoRng + rand::Rng {
    rand::rngs::OsRng
}

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

/// English vowels.
#[doc(hidden)]
pub const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];

/// English consonants.
#[doc(hidden)]
pub const CONSONANTS: &[char] = &[
    'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r',
    's', 't', 'v', 'w', 'x', 'y', 'z',
];

/// Numerical digits.
#[doc(hidden)]
pub const DIGITS: &[char] =
    &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
