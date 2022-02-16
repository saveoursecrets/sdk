//! Encapsulates an ECDSA private and public key pair.
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::types::*;

/// An ECDSA key pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(rename = "type")]
    type_id: u8,
    private: Vec<u8>,
    public: Vec<u8>,
}

impl KeyPair {
    /// Split a keypair into signing and verify parts (private/public).
    pub fn split(self) -> (KeyPart, KeyPart) {
        (
            KeyPart {
                type_id: self.type_id.clone(),
                key: self.private,
            },
            KeyPart {
                type_id: self.type_id.clone(),
                key: self.public,
            },
        )
    }
}

/// The private side of a key pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPart {
    /// Type identifier for the key.
    #[serde(rename = "type")]
    pub type_id: u8,
    /// Key data bytes.
    pub key: Vec<u8>,
}

/// Generate a new single party key pair.
pub fn generate() -> KeyPair {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verify_key = VerifyingKey::from(&signing_key);
    KeyPair {
        type_id: K256,
        private: signing_key.to_bytes().to_vec(),
        public: verify_key.to_bytes().to_vec(),
    }
}
