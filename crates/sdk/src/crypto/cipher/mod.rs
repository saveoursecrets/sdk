//! Constants for supported symmetric ciphers.
use super::{AeadPack, Nonce, PrivateKey};
use crate::{Error, Result};
use age::x25519::Recipient;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

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
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum Cipher {
    /// Cipher for XChaCha20Poly1305 encryption.
    XChaCha20Poly1305,
    /// Cipher for AES-GCM 256 bit encryption.
    AesGcm256,
    /// X25519 asymmetric encryption using AGE.
    X25519,
}

impl Cipher {
    /// Encrypt plaintext using this cipher.
    pub async fn encrypt_symmetric(
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
            _ => Err(Error::NotSymmetric),
        }
    }

    /// Decrypt ciphertext using this cipher.
    pub async fn decrypt_symmetric(
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
            _ => Err(Error::NotSymmetric),
        }
    }

    /// Encrypt plaintext using this cipher.
    pub async fn encrypt_asymmetric(
        &self,
        key: &PrivateKey,
        plaintext: &[u8],
        recipients: Vec<Recipient>,
    ) -> Result<AeadPack> {
        match self {
            Cipher::X25519 => match key {
                PrivateKey::Asymmetric(_) => {
                    x25519::encrypt(self, plaintext, recipients).await
                }
                _ => Err(Error::NotAsymmetric),
            },
            _ => Err(Error::NotAsymmetric),
        }
    }

    /// Decrypt ciphertext using this cipher.
    pub async fn decrypt_asymmetric(
        &self,
        key: &PrivateKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self {
            Cipher::X25519 => match key {
                PrivateKey::Asymmetric(identity) => {
                    x25519::decrypt(self, identity, aead).await
                }
                _ => Err(Error::NotAsymmetric),
            },
            _ => Err(Error::NotAsymmetric),
        }
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Self::AesGcm256
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::XChaCha20Poly1305 => "x_chacha20_poly1305",
                Self::AesGcm256 => "aes_gcm_256",
                Self::X25519 => "age_x25519",
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
            "age_x25519" => Ok(Self::X25519),
            _ => Err(Error::InvalidCipher(s.to_string())),
        }
    }
}

impl From<&Cipher> for u8 {
    fn from(value: &Cipher) -> Self {
        match value {
            Cipher::XChaCha20Poly1305 => X_CHACHA20_POLY1305,
            Cipher::AesGcm256 => AES_GCM_256,
            Cipher::X25519 => X25519,
        }
    }
}

impl TryFrom<u8> for Cipher {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            X_CHACHA20_POLY1305 => Ok(Cipher::XChaCha20Poly1305),
            AES_GCM_256 => Ok(Cipher::AesGcm256),
            X25519 => Ok(Cipher::X25519),
            _ => Err(Error::InvalidCipher(value.to_string())),
        }
    }
}
