//! Utilities for converting a password to a private key
//! and for generating a salt string and verifying a password
//! and salt.
use crate::Result;
use rand::Rng;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};

/// Encapsulates the bytes for a symmetric secret key.
///
/// Currently there is only a single variant but this type exists
/// if we need to use different key sizes in the future.
#[derive(Zeroize)]
pub enum SecretKey {
    /// Key of 32 bytes (256 bits).
    Key32([u8; 32]),
}

impl SecretKey {
    /// Create a new random 32 byte secret key.
    pub fn new_random_32() -> Self {
        let bytes: [u8; 32] = rand::thread_rng().gen();
        SecretKey::Key32(bytes)
    }

    /// Generate a new salt string.
    pub fn generate_salt() -> SaltString {
        SaltString::generate(&mut rand::thread_rng())
    }

    /// Parse a saved salt string.
    pub fn parse_salt<S: AsRef<str>>(salt: S) -> Result<SaltString> {
        Ok(SaltString::new(salt.as_ref())?)
    }

    /// Derive a secret key from a passphrase and salt.
    ///
    /// Hash a password using the given salt and convert to a 32 byte
    /// private key using the keccak256 hashing algorithm.
    pub fn derive_32<S: AsRef<str>>(
        password: S,
        salt: &SaltString,
    ) -> Result<SecretKey> {
        let password_hash = hash_password(password, salt)?;
        let hash = Keccak256::digest(password_hash.to_string().as_bytes());
        let hash: [u8; 32] = hash.as_slice().try_into()?;
        Ok(SecretKey::Key32(hash))
    }
}

impl From<SecretKey> for [u8; 32] {
    fn from(key: SecretKey) -> [u8; 32] {
        match key {
            SecretKey::Key32(bytes) => bytes,
        }
    }
}

impl SecretKey {
    /// Get a slice of the private key byte array.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Key32(ref bytes) => bytes,
        }
    }
}

/// Hash a password using the given salt and the Argon2 algorithm.
fn hash_password<S: AsRef<str>>(
    password: S,
    salt: &SaltString,
) -> Result<PasswordHash> {
    let argon2 = Argon2::default();
    let password_hash =
        argon2.hash_password(password.as_ref().as_bytes(), salt)?;
    Ok(password_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2() {
        let password = "My super secret password";
        let salt = SecretKey::generate_salt();
        let hash = hash_password(password, &salt);
        assert!(hash.is_ok());

        let key = SecretKey::derive_32(password, &salt);
        assert!(key.is_ok());

        let salt = SecretKey::parse_salt(&salt);
        assert!(salt.is_ok());
    }
}
