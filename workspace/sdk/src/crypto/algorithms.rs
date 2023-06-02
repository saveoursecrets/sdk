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
pub enum Algorithm {
    /// Algorithm for XChaCha20Poly1305 encryption.
    XChaCha20Poly1305,
    /// Algorithm for AES-GCM 256 bit encryption.
    AesGcm256,
}

impl Algorithm {
    /// Encrypt plaintext using this algorithm.
    pub fn encrypt(
        &self,
        key: &DerivedPrivateKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self {
            Algorithm::XChaCha20Poly1305 => {
                let nonce = Nonce::new_random_24();
                xchacha20poly1305::encrypt(key, plaintext, Some(nonce))
            }
            Algorithm::AesGcm256 => {
                let nonce = Nonce::new_random_12();
                aesgcm256::encrypt(key, plaintext, Some(nonce))
            }
        }
    }

    /// Decrypt ciphertext using this algorithm.
    pub fn decrypt(
        &self,
        key: &DerivedPrivateKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self {
            Algorithm::XChaCha20Poly1305 => {
                xchacha20poly1305::decrypt(key, aead)
            }
            Algorithm::AesGcm256 => aesgcm256::decrypt(key, aead),
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::XChaCha20Poly1305
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::XChaCha20Poly1305 => "x_chacha20_poly1305",
                Self::AesGcm256 => "aes_gcm_256",
            }
        })
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "x_chacha20_poly1305" => Ok(Self::XChaCha20Poly1305),
            "aes_gcm_256" => Ok(Self::AesGcm256),
            _ => Err(Error::InvalidAlgorithm(s.to_string())),
        }
    }
}

impl From<&Algorithm> for u8 {
    fn from(value: &Algorithm) -> Self {
        match value {
            Algorithm::XChaCha20Poly1305 => X_CHACHA20_POLY1305,
            Algorithm::AesGcm256 => AES_GCM_256,
        }
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            X_CHACHA20_POLY1305 => Ok(Algorithm::XChaCha20Poly1305),
            AES_GCM_256 => Ok(Algorithm::AesGcm256),
            _ => Err(Error::InvalidAlgorithm(value.to_string())),
        }
    }
}
