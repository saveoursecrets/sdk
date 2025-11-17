//! Password generation and helpers for the
//! [Save Our Secrets](https://saveoursecrets.com) SDK.
#![allow(clippy::len_without_is_empty)]

pub mod diceware;
mod error;
pub mod generator;
mod memorable;

pub use error::Error;
pub use memorable::memorable_password;

pub use zxcvbn;

use secrecy::SecretString;

/// Standard memorable password generation.
///
/// Uses three words.
pub fn memorable() -> SecretString {
    SecretString::new(memorable_password(3).into())
}

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

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
