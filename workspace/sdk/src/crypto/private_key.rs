//! Private key types.
use argon2::password_hash::SaltString;

use rand::Rng;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::Digest;
use std::convert::AsRef;

use crate::{
    crypto::{csprng, KeyDerivation, Seed},
    Result,
};

/// Access key used to unlock a vault.
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
        kdf: &KeyDerivation,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<PrivateKey> {
        match self {
            Self::Password(ref password) => {
                let deriver = kdf.deriver();
                Ok(PrivateKey::Symmetric(
                    deriver.derive(password, salt, seed)?,
                ))
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
