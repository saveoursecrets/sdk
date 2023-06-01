//! Constants for supported key derivation functions.
use crate::{Error, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{convert::AsRef, fmt, str::FromStr};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::Balloon;

/// Argon2 key derivation function.
pub const ARGON_2: u8 = 0x01;

/// Balloon hash key derivation function.
pub const BALLOON_HASH: u8 = 0x02;

/// Supported algorithms.
pub const KDFS: [u8; 2] = [ARGON_2, BALLOON_HASH];

mod derived_key;

#[deprecated]
pub mod secret_key;

pub use derived_key::DerivedPrivateKey;

/// Number of bytes for the passphrase seed entropy.
pub(crate) const SEED_SIZE: usize = 32;

/// Type for additional passphrase seed entropy.
pub type Seed = [u8; SEED_SIZE];

/// Generate new random seed entropy.
pub fn generate_seed() -> Seed {
    let seed: Seed = rand::thread_rng().gen();
    seed
}

/// Supported key derivation functions.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum KeyDerivationFunction {
    /// Argon2 key derivation function.
    Argon2(u8),
    /// Balloon hash key derivation function.
    BalloonHash(u8),
}

impl KeyDerivationFunction {
    /// Get the deriver for this key derivation function.
    pub fn deriver(&self) -> Box<dyn Deriver> {
        match self {
            KeyDerivationFunction::Argon2(_) => Box::new(Argon2Deriver),
            KeyDerivationFunction::BalloonHash(_) => {
                Box::new(BalloonHashDeriver)
            }
        }
    }
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
                Self::BalloonHash(_) => "balloon_hash",
            }
        })
    }
}

impl FromStr for KeyDerivationFunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "argon_2" => Ok(Self::Argon2(ARGON_2)),
            "balloon_hash" => Ok(Self::BalloonHash(BALLOON_HASH)),
            _ => Err(Error::InvalidKeyDerivationFunction(s.to_string())),
        }
    }
}

impl From<KeyDerivationFunction> for u8 {
    fn from(value: KeyDerivationFunction) -> Self {
        match value {
            KeyDerivationFunction::Argon2(id)
            | KeyDerivationFunction::BalloonHash(id) => id,
        }
    }
}

impl TryFrom<u8> for KeyDerivationFunction {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            ARGON_2 => Ok(KeyDerivationFunction::Argon2(value)),
            _ => Err(Error::InvalidKeyDerivationFunction(value.to_string())),
        }
    }
}

impl AsRef<u8> for KeyDerivationFunction {
    fn as_ref(&self) -> &u8 {
        match self {
            KeyDerivationFunction::Argon2(ref id)
            | KeyDerivationFunction::BalloonHash(ref id) => id,
        }
    }
}

/// Trait for types that can derive a private key.
pub trait Deriver {
    /// Hash a password using the given salt.
    fn hash_password<'a>(
        &self,
        password: &[u8],
        salt: &'a SaltString,
    ) -> Result<PasswordHash<'a>>;

    /// Derive a 32 byte secret key from a passphrase, salt and
    /// optional seed entropy.
    fn derive_32(
        &self,
        password: &str,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<DerivedPrivateKey> {
        let buffer = if let Some(seed) = seed {
            let mut buffer = password.as_bytes().to_vec();
            buffer.extend_from_slice(seed.as_slice());
            buffer
        } else {
            password.as_bytes().to_vec()
        };

        let password_hash = self.hash_password(buffer.as_slice(), salt)?;
        let hash = Sha256::digest(password_hash.to_string().as_bytes());
        let hash: [u8; 32] = hash.as_slice().try_into()?;
        Ok(DerivedPrivateKey::Key32(secrecy::Secret::new(hash)))
    }
}

/// Derive a private key using the Argon2 
/// key derivation function.
pub struct Argon2Deriver;

impl Deriver for Argon2Deriver {
    fn hash_password<'a>(
        &self,
        password: &[u8],
        salt: &'a SaltString,
    ) -> Result<PasswordHash<'a>> {
        let argon2 = Argon2::default();
        Ok(argon2.hash_password(password, salt)?)
    }
}

/// Derive a private key using the Balloon Hash 
/// key derivation function.
pub struct BalloonHashDeriver;

impl Deriver for BalloonHashDeriver {
    fn hash_password<'a>(
        &self,
        password: &[u8],
        salt: &'a SaltString,
    ) -> Result<PasswordHash<'a>> {
        let balloon = Balloon::<Sha256>::default();
        Ok(balloon.hash_password(password, salt)?)
    }
}
