//! Utilities for converting a password to a private key
//! and for generating a salt string and verifying a password
//! and salt.
use crate::Result;
use sha3::{Digest, Keccak256};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};

/// Generate a new salt string.
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut rand::thread_rng())
}

/// Parse a saved salt string.
pub fn parse_salt<S: AsRef<str>>(salt: S) -> Result<SaltString> {
    Ok(SaltString::new(salt.as_ref())?)
}

/// Hash a password using the given salt.
fn hash_password<S: AsRef<str>>(password: S, salt: &SaltString) -> Result<PasswordHash> {
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_ref().as_bytes(), salt)?;
    Ok(password_hash)
}

/// Hash a password using the given salt and convert to a 32 byte
/// private key using the keccak256 hashing algorithm.
pub fn generate_secret_key<S: AsRef<str>>(password: S, salt: &SaltString) -> Result<[u8; 32]> {
    let password_hash = hash_password(password, salt)?;
    let hash = Keccak256::digest(password_hash.to_string().as_bytes());
    let hash: [u8; 32] = hash.as_slice().try_into()?;
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2() {
        let password = "My super secret password";
        let salt = generate_salt();
        let hash = hash_password(password, &salt);
        assert!(hash.is_ok());

        let key = private_key(password, &salt);
        assert!(key.is_ok());

        let salt = parse_salt(&salt);
        assert!(salt.is_ok());
    }
}
