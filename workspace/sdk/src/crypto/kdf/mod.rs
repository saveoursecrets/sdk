//! Constants for supported key derivation functions.
use crate::{crypto::csprng, Error, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{convert::AsRef, fmt, str::FromStr};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::Balloon;

/// Argon2 key derivation function.
pub(crate) const ARGON_2_ID: u8 = 1;
/// Balloon hash key derivation function.
pub(crate) const BALLOON_HASH: u8 = 2;

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
    let seed: Seed = csprng().gen();
    seed
}

/// Supported key derivation functions.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum KeyDerivation {
    /// Argon2 key derivation function.
    Argon2Id(u8),
    /// Balloon hash key derivation function.
    BalloonHash(u8),
}

impl KeyDerivation {
    /// Get the deriver for this key derivation function.
    pub fn deriver(&self) -> Box<dyn Deriver<Sha256>> {
        match self {
            KeyDerivation::Argon2Id(_) => Box::new(Argon2IdDeriver),
            KeyDerivation::BalloonHash(_) => Box::new(BalloonHashDeriver),
        }
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::Argon2Id(ARGON_2_ID)
    }
}

impl fmt::Display for KeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::Argon2Id(_) => "argon_2_id",
                Self::BalloonHash(_) => "balloon_hash",
            }
        })
    }
}

impl FromStr for KeyDerivation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "argon_2_id" => Ok(Self::Argon2Id(ARGON_2_ID)),
            "balloon_hash" => Ok(Self::BalloonHash(BALLOON_HASH)),
            _ => Err(Error::InvalidKeyDerivation(s.to_string())),
        }
    }
}

impl From<KeyDerivation> for u8 {
    fn from(value: KeyDerivation) -> Self {
        match value {
            KeyDerivation::Argon2Id(id) | KeyDerivation::BalloonHash(id) => {
                id
            }
        }
    }
}

impl TryFrom<u8> for KeyDerivation {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            ARGON_2_ID => KeyDerivation::Argon2Id(value),
            BALLOON_HASH => KeyDerivation::BalloonHash(value),
            _ => return Err(Error::InvalidKeyDerivation(value.to_string())),
        })
    }
}

impl AsRef<u8> for KeyDerivation {
    fn as_ref(&self) -> &u8 {
        match self {
            KeyDerivation::Argon2Id(ref id)
            | KeyDerivation::BalloonHash(ref id) => id,
        }
    }
}

/// Trait for types that can derive a private key.
pub trait Deriver<D: Digest> {
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
        let hash = D::digest(password_hash.to_string().as_bytes());
        let hash: [u8; 32] = hash.as_slice().try_into()?;
        Ok(DerivedPrivateKey::Key32(secrecy::Secret::new(hash)))
    }
}

/// Derive a private key using the Argon2
/// key derivation function.
pub struct Argon2IdDeriver;

impl Deriver<Sha256> for Argon2IdDeriver {
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

impl Deriver<Sha256> for BalloonHashDeriver {
    fn hash_password<'a>(
        &self,
        password: &[u8],
        salt: &'a SaltString,
    ) -> Result<PasswordHash<'a>> {
        let balloon = Balloon::<Sha256>::default();
        Ok(balloon.hash_password(password, salt)?)
    }
}
