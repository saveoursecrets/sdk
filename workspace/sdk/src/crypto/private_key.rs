//! Private key types.
use crate::{crypto::csprng, Error, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::Balloon;
use rand::Rng;
use secrecy::{ExposeSecret, SecretVec};
use sha2::{Digest, Sha256};
use std::{convert::AsRef, fmt, str::FromStr};

/// Private key variants.
pub enum PrivateKey {
    /// Private key used for symmetric ciphers.
    Symmetric(DerivedPrivateKey),
    /// Private key used for asymmetric ciphers.
    Asymmetric {
        identity: age::x25519::Identity,
        recipients: Vec<age::x25519::Recipient>,
    },
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

