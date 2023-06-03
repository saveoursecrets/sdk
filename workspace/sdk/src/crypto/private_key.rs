//! Private key types.
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::Balloon;
use rand::Rng;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::{Digest, Sha256};
use std::{convert::AsRef, fmt, str::FromStr};

use crate::{
    crypto::{csprng, KeyDerivation, Seed},
    Error, Result,
};

/// Access key is converted to a private key to access a vault.
pub enum AccessKey {
    /// Password access.
    Password(SecretString),
    /// Asymmetric private key.
    Key(age::x25519::Identity),
}

impl AccessKey {
    /// Convert this access key into a private key.
    pub fn into_private(
        self,
        kdf: KeyDerivation,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<PrivateKey> {
        match self {
            Self::Password(password) => {
                let deriver = kdf.deriver();
                Ok(PrivateKey::Symmetric(deriver.derive(
                    password.expose_secret(),
                    salt,
                    seed,
                )?))
            }
            Self::Key(key) => Ok(PrivateKey::Asymmetric(key)),
        }
    }
}

/// Private key variants.
pub enum PrivateKey {
    /// Private key used for symmetric ciphers.
    Symmetric(DerivedPrivateKey),
    /// Private key used for asymmetric ciphers.
    Asymmetric(age::x25519::Identity),
}

/// Encapsulates the bytes for a derived symmetric secret key.
pub struct DerivedPrivateKey {
    inner: SecretVec<u8>,
}

impl DerivedPrivateKey {
    /// Create a new random 32-byte secret key.
    #[cfg(test)]
    pub fn generate() -> Self {
        let bytes: [u8; 32] = csprng().gen();
        Self {
            inner: SecretVec::new(bytes.to_vec()),
        }
    }

    /// Create a new derived private key.
    pub(crate) fn new(inner: SecretVec<u8>) -> Self {
        Self { inner }
    }
}

impl AsRef<[u8]> for DerivedPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.expose_secret()
    }
}
