//! Secret key type for deriving a private key from a passphrase.
use crate::{crypto::csprng, Result};
use rand::Rng;
use sha3::{Digest, Keccak256};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};

use secrecy::ExposeSecret;

/// Number of bytes for the passphrase seed entropy.
pub(crate) const SEED_SIZE: usize = 32;

/// Type for additional passphrase seed entropy.
pub type Seed = [u8; SEED_SIZE];

/// Generate new random seed entropy.
pub fn generate_seed() -> Seed {
    let seed: Seed = csprng().gen();
    seed
}

/// Encapsulates the bytes for a symmetric secret key.
///
/// Currently there is only a single variant but this type exists
/// if we need to use different key sizes in the future.
pub enum SecretKey {
    /// Key of 32 bytes (256 bits).
    Key32(secrecy::Secret<[u8; 32]>),
}

impl SecretKey {
    /// Create a new random 32 byte secret key.
    #[cfg(test)]
    pub fn new_random_32() -> Self {
        let bytes: [u8; 32] = csprng().gen();
        SecretKey::Key32(secrecy::Secret::new(bytes))
    }

    /// Generate a new salt string.
    pub fn generate_salt() -> SaltString {
        SaltString::generate(&mut csprng())
    }

    /// Parse a saved salt string.
    pub fn parse_salt<S: AsRef<str>>(salt: S) -> Result<SaltString> {
        Ok(SaltString::from_b64(salt.as_ref())?)
    }

    /// Derive a secret key from a passphrase, salt and optional seed entropy.
    ///
    /// Hash a password using the given salt and Argon2 algorithm then
    /// convert to a 32 byte private key using the keccak256 hashing
    /// algorithm.
    pub fn derive_32<S: AsRef<str>>(
        password: S,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<SecretKey> {
        let buffer = if let Some(seed) = seed {
            let mut buffer = password.as_ref().as_bytes().to_vec();
            buffer.extend_from_slice(seed.as_slice());
            buffer
        } else {
            password.as_ref().as_bytes().to_vec()
        };

        let password_hash = hash_password(buffer.as_slice(), salt)?;
        let hash = Keccak256::digest(password_hash.to_string().as_bytes());
        let hash: [u8; 32] = hash.as_slice().try_into()?;
        Ok(SecretKey::Key32(secrecy::Secret::new(hash)))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Key32(ref bytes) => bytes.expose_secret(),
        }
    }
}

/// Hash a password using the given salt and the Argon2 algorithm.
fn hash_password<'a>(
    password: &[u8],
    salt: &'a SaltString,
) -> Result<PasswordHash<'a>> {
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, salt)?;
    Ok(password_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2() {
        let password = "My super secret password";
        let salt = SecretKey::generate_salt();
        let hash = hash_password(password.as_bytes(), &salt);
        assert!(hash.is_ok());

        let key = SecretKey::derive_32(password, &salt, None);
        assert!(key.is_ok());

        let salt = SecretKey::parse_salt(&salt);
        assert!(salt.is_ok());
    }
}
