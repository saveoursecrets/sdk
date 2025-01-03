//! Cryptographic routines and types.
use crate::csprng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

#[doc(hidden)]
pub mod cipher;
mod key_derivation;
mod private_key;

pub use cipher::Cipher;
pub use cipher::{AES_GCM_256, X25519, X_CHACHA20_POLY1305};

#[doc(hidden)]
pub use key_derivation::{Deriver, SEED_SIZE};
pub(crate) use key_derivation::{ARGON_2_ID, BALLOON_HASH};

pub use key_derivation::{KeyDerivation, Seed};
pub use private_key::{AccessKey, DerivedPrivateKey, PrivateKey};

/// Enumeration of the sizes for nonces.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Nonce {
    /// Standard 12 byte nonce used by AES-GCM.
    Nonce12(#[serde_as(as = "Base64")] [u8; 12]),
    /// Extended 24 byte nonce used by XChaCha20Poly1305.
    Nonce24(#[serde_as(as = "Base64")] [u8; 24]),
}

impl Nonce {
    /// Generate a new random 12 byte nonce.
    pub fn new_random_12() -> Nonce {
        let val: [u8; 12] = csprng().gen();
        Nonce::Nonce12(val)
    }

    /// Generate a new random 24 byte nonce.
    pub fn new_random_24() -> Nonce {
        let val: [u8; 24] = csprng().gen();
        Nonce::Nonce24(val)
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce::Nonce24([0; 24])
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        match self {
            Nonce::Nonce12(ref val) => val,
            Nonce::Nonce24(ref val) => val,
        }
    }
}

/// Encrypted data with the nonce.
#[serde_as]
#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq, Clone)]
pub struct AeadPack {
    /// Number once value.
    pub nonce: Nonce,
    /// Encrypted cipher text.
    #[serde_as(as = "Base64")]
    pub ciphertext: Vec<u8>,
}
