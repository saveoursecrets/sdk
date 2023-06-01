//! Constants for supported key derivation functions.
use crate::Error;

use std::{convert::AsRef, fmt, str::FromStr};

/// Argon2 key derivation function.
pub const ARGON_2: u8 = 0x01;

/// Supported algorithms.
pub const KDFS: [u8; 1] = [ARGON_2];

/// Supported key derivation functions.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum KeyDerivationFunction {
    /// Argon2 key derivation function.
    Argon2(u8),
}

impl Default for KeyDerivationFunction {
    fn default() -> Self {
        Self::Argon2(ARGON_2)
    }
}

impl fmt::Display for KeyDerivationFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::Argon2(_) => "argon_2",
            }
        })
    }
}

impl FromStr for KeyDerivationFunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "argon_2" => Ok(Self::default()),
            _ => Err(Error::InvalidKeyDerivationFunction(s.to_string())),
        }
    }
}

impl From<KeyDerivationFunction> for u8 {
    fn from(value: KeyDerivationFunction) -> Self {
        match value {
            KeyDerivationFunction::Argon2(id) => id,
        }
    }
}

impl TryFrom<u8> for KeyDerivationFunction {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            ARGON_2 => {
                Ok(KeyDerivationFunction::Argon2(value))
            }
            _ => Err(Error::InvalidKeyDerivationFunction(value.to_string())),
        }
    }
}

impl AsRef<u8> for KeyDerivationFunction {
    fn as_ref(&self) -> &u8 {
        match self {
            KeyDerivationFunction::Argon2(ref id) => id,
        }
    }
}

