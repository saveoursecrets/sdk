//! Derived private key from a passphrase.
use crate::{crypto::csprng, Result};
use rand::Rng;
use sha3::{Digest, Keccak256};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};

use secrecy::ExposeSecret;

/// Encapsulates the bytes for a derived symmetric secret key.
///
/// Currently there is only a single variant but this type exists
/// if we need to use different key sizes in the future.
pub enum DerivedPrivateKey {
    /// Key of 32 bytes (256 bits).
    Key32(secrecy::Secret<[u8; 32]>),
}

impl DerivedPrivateKey {
    /// Create a new random 32 byte secret key.
    #[cfg(test)]
    pub fn new_random_32() -> Self {
        let bytes: [u8; 32] = csprng().gen();
        DerivedPrivateKey::Key32(secrecy::Secret::new(bytes))
    }

    /// Generate a new salt string.
    pub fn generate_salt() -> SaltString {
        SaltString::generate(&mut csprng())
    }

    /// Parse a saved salt string.
    pub fn parse_salt<S: AsRef<str>>(salt: S) -> Result<SaltString> {
        Ok(SaltString::from_b64(salt.as_ref())?)
    }
}

impl AsRef<[u8]> for DerivedPrivateKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Key32(ref bytes) => bytes.expose_secret(),
        }
    }
}
