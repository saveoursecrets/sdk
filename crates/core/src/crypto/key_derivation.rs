//! Constants for supported key derivation functions.
use crate::{
    crypto::{csprng, DerivedPrivateKey},
    Error, Result,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use balloon_hash::Balloon;
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::{convert::AsRef, fmt, str::FromStr};

/// Argon2 key derivation function.
pub(crate) const ARGON_2_ID: u8 = 1;
/// Balloon hash key derivation function.
pub(crate) const BALLOON_HASH: u8 = 2;

/// Type for additional passphrase seed entropy.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Seed(#[serde_as(as = "Base64")] pub [u8; Seed::SIZE]);

impl Seed {
    /// Number of bytes for seed entropy.
    pub const SIZE: usize = 32;
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Supported key derivation functions.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum KeyDerivation {
    /// Argon2 key derivation function.
    Argon2Id,
    /// Balloon hash key derivation function.
    BalloonHash,
}

impl KeyDerivation {
    /// Get the deriver for this key derivation function.
    pub fn deriver(&self) -> Box<dyn Deriver<Sha256> + Send + 'static> {
        match self {
            KeyDerivation::Argon2Id => Box::new(Argon2IdDeriver),
            KeyDerivation::BalloonHash => Box::new(BalloonHashDeriver),
        }
    }

    /// Generate a new salt string.
    pub fn generate_salt() -> SaltString {
        SaltString::generate(&mut csprng())
    }

    /// Parse a saved salt string.
    pub fn parse_salt<S: AsRef<str>>(salt: S) -> Result<SaltString> {
        Ok(SaltString::from_b64(salt.as_ref())?)
    }

    /// Generate new random seed entropy.
    #[deprecated]
    pub fn generate_seed() -> Seed {
        let bytes: [u8; Seed::SIZE] = csprng().gen();
        Seed(bytes)
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::Argon2Id
    }
}

impl fmt::Display for KeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::Argon2Id => "argon_2_id",
                Self::BalloonHash => "balloon_hash",
            }
        })
    }
}

impl FromStr for KeyDerivation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "argon_2_id" => Ok(Self::Argon2Id),
            "balloon_hash" => Ok(Self::BalloonHash),
            _ => Err(Error::InvalidKeyDerivation(s.to_string())),
        }
    }
}

impl From<&KeyDerivation> for u8 {
    fn from(value: &KeyDerivation) -> Self {
        match value {
            KeyDerivation::Argon2Id => ARGON_2_ID,
            KeyDerivation::BalloonHash => BALLOON_HASH,
        }
    }
}

impl TryFrom<u8> for KeyDerivation {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            ARGON_2_ID => KeyDerivation::Argon2Id,
            BALLOON_HASH => KeyDerivation::BalloonHash,
            _ => return Err(Error::InvalidKeyDerivation(value.to_string())),
        })
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

    /// Derive a private secret key from a passphrase, salt and
    /// optional seed entropy.
    fn derive(
        &self,
        password: &SecretString,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<DerivedPrivateKey> {
        let buffer = if let Some(seed) = seed {
            let mut buffer = password.expose_secret().as_bytes().to_vec();
            buffer.extend_from_slice(seed.as_ref());
            buffer
        } else {
            password.expose_secret().as_bytes().to_vec()
        };

        let password_hash = self.hash_password(buffer.as_slice(), salt)?;
        let password_hash_string = password_hash.serialize();
        let hash = D::digest(password_hash_string.as_bytes());
        Ok(DerivedPrivateKey::new(secrecy::SecretBox::new(
            hash.as_slice().to_vec().into(),
        )))
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
