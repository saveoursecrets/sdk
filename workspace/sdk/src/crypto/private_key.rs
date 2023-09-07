//! Private key types.
use age::x25519::Identity;
use argon2::password_hash::SaltString;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::convert::AsRef;
use std::fmt;

use crate::{
    crypto::{KeyDerivation, Seed},
    Result,
};

/// Access key used to unlock a vault.
#[derive(Clone)]
pub enum AccessKey {
    /// Password access.
    Password(SecretString),
    /// Asymmetric private key.
    Identity(Identity),
}

impl From<SecretString> for AccessKey {
    fn from(value: SecretString) -> Self {
        Self::Password(value)
    }
}

impl From<Identity> for AccessKey {
    fn from(value: Identity) -> Self {
        Self::Identity(value)
    }
}

impl From<AccessKey> for SecretString {
    fn from(value: AccessKey) -> Self {
        match value {
            AccessKey::Password(password) => password,
            AccessKey::Identity(id) => id.to_string(),
        }
    }
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
            Self::Identity(id) => Ok(PrivateKey::Asymmetric(id)),
        }
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.debug_struct("Password").finish(),
            Self::Identity(_) => f.debug_struct("Identity").finish(),
        }
    }
}

impl PartialEq for AccessKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Password(a), Self::Password(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            (Self::Identity(a), Self::Identity(b)) => {
                a.to_string().expose_secret() == b.to_string().expose_secret()
            }
            _ => false,
        }
    }
}

impl Eq for AccessKey {}

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
    pub fn generate() -> Self {
        use crate::crypto::csprng;
        use rand::Rng;
        let bytes: [u8; 32] = csprng().gen();
        Self {
            inner: SecretVec::new(bytes.to_vec()),
        }
    }

    /// Convert from a PEM-encoded key.
    pub fn from_pem(key: &str) -> Result<Self> {
        let pem = pem::parse(key)?;
        let contents = pem.contents();
        Ok(Self {
            inner: SecretVec::new(contents.to_vec()),
        })
    }

    /// Convert this key to a PEM-encoded string.
    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            self.inner.expose_secret().as_slice(),
        ))
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
