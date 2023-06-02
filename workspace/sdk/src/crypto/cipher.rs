//! Constants for supported symmetric ciphers.
use super::{
    aesgcm256, xchacha20poly1305, AeadPack, DerivedPrivateKey, Nonce,
};
use crate::{Error, Result};
use std::{fmt, str::FromStr};

/// Extended ChaCha20 Poly1305 cipher.
pub const X_CHACHA20_POLY1305: u8 = 1;

/// AES-GCM 256 cipher.
pub const AES_GCM_256: u8 = 2;

/// Supported cipher algorithms.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum Cipher {
    /// Cipher for XChaCha20Poly1305 encryption.
    XChaCha20Poly1305,
    /// Cipher for AES-GCM 256 bit encryption.
    AesGcm256,
}

impl Cipher {
    /// Encrypt plaintext using this cipher.
    pub async fn encrypt(
        &self,
        key: &DerivedPrivateKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self {
            Cipher::XChaCha20Poly1305 => {
                let nonce = Nonce::new_random_24();
                xchacha20poly1305::encrypt(key, plaintext, Some(nonce)).await
            }
            Cipher::AesGcm256 => {
                let nonce = Nonce::new_random_12();
                aesgcm256::encrypt(key, plaintext, Some(nonce)).await
            }
        }
    }

    /// Decrypt ciphertext using this cipher.
    pub async fn decrypt(
        &self,
        key: &DerivedPrivateKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self {
            Cipher::XChaCha20Poly1305 => {
                xchacha20poly1305::decrypt(key, aead).await
            }
            Cipher::AesGcm256 => aesgcm256::decrypt(key, aead).await,
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
            _ => Err(Error::InvalidCipher(s.to_string())),
        }
    }
}

impl From<&Cipher> for u8 {
    fn from(value: &Cipher) -> Self {
        match value {
            Cipher::XChaCha20Poly1305 => X_CHACHA20_POLY1305,
            Cipher::AesGcm256 => AES_GCM_256,
        }
    }
}

impl TryFrom<u8> for Cipher {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            X_CHACHA20_POLY1305 => Ok(Cipher::XChaCha20Poly1305),
            AES_GCM_256 => Ok(Cipher::AesGcm256),
            _ => Err(Error::InvalidCipher(value.to_string())),
        }
    }
}
