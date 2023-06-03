//! Constants for supported symmetric ciphers.
use super::{AeadPack, Nonce, PrivateKey};
use crate::{Error, Result};
use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

mod aesgcm256;
mod x25519;
mod xchacha20poly1305;

/// Extended ChaCha20 Poly1305 cipher.
pub const X_CHACHA20_POLY1305: u8 = 1;

/// AES-GCM 256 cipher.
pub const AES_GCM_256: u8 = 2;

/// X25519 asymmetric cipher using AGE.
pub const X25519: u8 = 3;

/// Supported cipher algorithms.
#[derive(Clone)]
pub enum Cipher {
    /// Cipher for XChaCha20Poly1305 encryption.
    XChaCha20Poly1305,
    /// Cipher for AES-GCM 256 bit encryption.
    AesGcm256,
    /// X25519 asymmetric encryption using AGE.
    X25519(Vec<age::x25519::Recipient>),
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XChaCha20Poly1305 => {
                f.debug_struct("XChaCha20Poly1305").finish()
            }
            Self::AesGcm256 => f.debug_struct("AesGcm256").finish(),
            Self::X25519(recipients) => {
                let recipients: Vec<String> =
                    recipients.into_iter().map(|r| r.to_string()).collect();
                f.debug_struct("X25519")
                    .field("recipients", &recipients)
                    .finish()
            }
        }
    }
}

impl PartialEq for Cipher {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::XChaCha20Poly1305, Self::XChaCha20Poly1305) => true,
            (Self::AesGcm256, Self::AesGcm256) => true,
            (Self::X25519(a), Self::X25519(b)) => {
                let a: Vec<String> =
                    a.into_iter().map(|r| r.to_string()).collect();
                let b: Vec<String> =
                    b.into_iter().map(|r| r.to_string()).collect();
                a == b
            }
            _ => false,
        }
    }
}

impl Eq for Cipher {}

impl Hash for Cipher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::XChaCha20Poly1305 => Self::XChaCha20Poly1305.hash(state),
            Self::AesGcm256 => Self::AesGcm256.hash(state),
            Self::X25519(recipients) => {
                for recipient in recipients {
                    recipient.to_string().hash(state);
                }
            }
        }
    }
}

impl Cipher {
    /// Encrypt plaintext using this cipher.
    pub async fn encrypt(
        &self,
        key: &PrivateKey,
        plaintext: &[u8],
        nonce: Option<Nonce>,
    ) -> Result<AeadPack> {
        match self {
            Cipher::XChaCha20Poly1305 => match key {
                PrivateKey::Symmetric(key) => {
                    xchacha20poly1305::encrypt(self, key, plaintext, nonce)
                        .await
                }
                _ => Err(Error::NotSymmetric),
            },
            Cipher::AesGcm256 => match key {
                PrivateKey::Symmetric(key) => {
                    aesgcm256::encrypt(self, key, plaintext, nonce).await
                }
                _ => Err(Error::NotSymmetric),
            },
            Cipher::X25519(_) => match key {
                PrivateKey::Asymmetric(_) => {
                    x25519::encrypt(self, plaintext).await
                }
                _ => Err(Error::NotAsymmetric),
            },
        }
    }

    /// Decrypt ciphertext using this cipher.
    pub async fn decrypt(
        &self,
        key: &PrivateKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self {
            Cipher::XChaCha20Poly1305 => match key {
                PrivateKey::Symmetric(key) => {
                    xchacha20poly1305::decrypt(self, key, aead).await
                }
                _ => Err(Error::NotSymmetric),
            },
            Cipher::AesGcm256 => match key {
                PrivateKey::Symmetric(key) => {
                    aesgcm256::decrypt(self, key, aead).await
                }
                _ => Err(Error::NotSymmetric),
            },
            Cipher::X25519(_) => match key {
                PrivateKey::Asymmetric(identity) => {
                    x25519::decrypt(self, identity, aead).await
                }
                _ => Err(Error::NotAsymmetric),
            },
        }
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Self::XChaCha20Poly1305
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::XChaCha20Poly1305 => "x_chacha20_poly1305",
                Self::AesGcm256 => "aes_gcm_256",
                Self::X25519(_) => "age_x25519",
            }
        })
    }
}

impl FromStr for Cipher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "x_chacha20_poly1305" => Ok(Self::XChaCha20Poly1305),
            "aes_gcm_256" => Ok(Self::AesGcm256),
            "age_x25519" => Ok(Self::X25519(vec![])),
            _ => Err(Error::InvalidCipher(s.to_string())),
        }
    }
}

impl From<&Cipher> for u8 {
    fn from(value: &Cipher) -> Self {
        match value {
            Cipher::XChaCha20Poly1305 => X_CHACHA20_POLY1305,
            Cipher::AesGcm256 => AES_GCM_256,
            Cipher::X25519(_) => X25519,
        }
    }
}

impl TryFrom<u8> for Cipher {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            X_CHACHA20_POLY1305 => Ok(Cipher::XChaCha20Poly1305),
            AES_GCM_256 => Ok(Cipher::AesGcm256),
            X25519 => Ok(Cipher::X25519(vec![])),
            _ => Err(Error::InvalidCipher(value.to_string())),
        }
    }
}
