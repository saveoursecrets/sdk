//! Cryptographic routines and types.
use crate::Error;
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub mod aesgcm256;
pub mod secret_key;
pub mod xchacha20poly1305;

/// Generate a random ECDSA private signing key.
pub fn generate_random_ecdsa_signing_key() -> ([u8; 32], [u8; 33]) {
    use k256::ecdsa::SigningKey;
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let public_key = signing_key.verifying_key();
    let signing_bytes: [u8; 32] = signing_key
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("wrong byte length for private signing key");

    let public_bytes: [u8; 33] = public_key
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("wrong byte length for public signing key");

    (signing_bytes, public_bytes)
}

/// Constants for supported symmetric ciphers.
pub mod algorithms {
    use crate::Error;
    use binary_stream::{
        BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
    };
    use std::{convert::AsRef, fmt, str::FromStr};

    /// Default algorithm.
    pub const X_CHACHA20_POLY1305: u8 = 0x01;

    /// AES-GCM 256 bit.
    pub const AES_GCM_256: u8 = 0x02;

    /// All supported algorithms.
    pub const ALGORITHMS: [u8; 2] = [X_CHACHA20_POLY1305, AES_GCM_256];

    /// Wrapper type for cipher algorithm.
    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum Algorithm {
        /// Algorithm for XChaCha20Poly1305 encryption.
        XChaCha20Poly1305(u8),
        /// Algorithm for AES-GCM 256 bit encryption.
        AesGcm256(u8),
    }

    impl Algorithm {
        /// The AES-GCM 256 bit algorithm.
        pub fn aes() -> Self {
            Self::AesGcm256(AES_GCM_256)
        }
    }

    impl fmt::Display for Algorithm {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", {
                match self {
                    Self::XChaCha20Poly1305(_) => "X_CHACHA20_POLY1305",
                    Self::AesGcm256(_) => "AES_GCM_256",
                }
            })
        }
    }

    impl FromStr for Algorithm {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "x_chacha20_poly1305" => Ok(Self::default()),
                "aes_gcm_256" => Ok(Self::aes()),
                _ => Err(Error::InvalidAlgorithm(s.to_string())),
            }
        }
    }

    impl From<Algorithm> for u8 {
        fn from(value: Algorithm) -> Self {
            match value {
                Algorithm::XChaCha20Poly1305(id) => id,
                Algorithm::AesGcm256(id) => id,
            }
        }
    }

    impl AsRef<u8> for Algorithm {
        fn as_ref(&self) -> &u8 {
            match self {
                Algorithm::XChaCha20Poly1305(ref id) => id,
                Algorithm::AesGcm256(ref id) => id,
            }
        }
    }

    impl Default for Algorithm {
        fn default() -> Self {
            Self::XChaCha20Poly1305(X_CHACHA20_POLY1305)
        }
    }

    impl Encode for Algorithm {
        fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
            writer.write_u8(*self.as_ref())?;
            Ok(())
        }
    }

    impl Decode for Algorithm {
        fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
            let id = reader.read_u8()?;
            *self = match id {
                X_CHACHA20_POLY1305 => Algorithm::XChaCha20Poly1305(id),
                AES_GCM_256 => Algorithm::AesGcm256(id),
                _ => {
                    return Err(BinaryError::Boxed(Box::from(
                        Error::UnknownAlgorithm(id),
                    )));
                }
            };
            Ok(())
        }
    }
}

/// Enumeration of the sizes for nonces.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum Nonce {
    /// Standard 12 byte nonce used by AES-GCM and ChaCha20Poly1305.
    Nonce12([u8; 12]),
    /// Extended 24 byte nonce used by XChaCha20Poly1305.
    Nonce24([u8; 24]),
}

impl Nonce {
    /// Generate a new random 12 byte nonce.
    pub fn new_random_12() -> Nonce {
        let val: [u8; 12] = rand::thread_rng().gen();
        Nonce::Nonce12(val)
    }

    /// Generate a new random 24 byte nonce.
    pub fn new_random_24() -> Nonce {
        let val: [u8; 24] = rand::thread_rng().gen();
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
#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq, Clone)]
pub struct AeadPack {
    /// Number once value.
    pub nonce: Nonce,
    /// Encrypted cipher text.
    pub ciphertext: Vec<u8>,
}

impl Encode for AeadPack {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        match &self.nonce {
            Nonce::Nonce12(ref bytes) => {
                writer.write_u8(12)?;
                writer.write_bytes(bytes)?;
            }
            Nonce::Nonce24(ref bytes) => {
                writer.write_u8(24)?;
                writer.write_bytes(bytes)?;
            }
        }
        writer.write_u32(self.ciphertext.len() as u32)?;
        writer.write_bytes(&self.ciphertext)?;
        Ok(())
    }
}

impl Decode for AeadPack {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let nonce_size = reader.read_u8()?;
        let nonce_buffer = reader.read_bytes(nonce_size as usize)?;
        match nonce_size {
            12 => {
                self.nonce =
                    Nonce::Nonce12(nonce_buffer.as_slice().try_into()?)
            }
            24 => {
                self.nonce =
                    Nonce::Nonce24(nonce_buffer.as_slice().try_into()?)
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownNonceSize(nonce_size),
                )));
            }
        }
        let len = reader.read_u32()?;
        self.ciphertext = reader.read_bytes(len as usize)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::xchacha20poly1305::*;
    use crate::crypto::secret_key::SecretKey;
    use anyhow::Result;

    #[test]
    fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
        let key = SecretKey::new_random_32();
        let value = b"plaintext message";
        let aead = encrypt(&key, value, None)?;
        let plaintext = decrypt(&key, &aead)?;
        assert_eq!(&plaintext, value);
        Ok(())
    }

    #[test]
    fn xchacha20poly1305_encrypt_decrypt_tamper() {
        let key = SecretKey::new_random_32();
        let value = b"plaintext message";
        let mut aead = encrypt(&key, value, None).unwrap();

        // Flip all the bits
        aead.ciphertext = aead.ciphertext.iter().map(|b| !*b).collect();

        // Fails due to tampering
        assert!(decrypt(&key, &aead).is_err());
    }

    #[test]
    fn ecdsa_sign() {
        use k256::ecdsa::{
            signature::{Signer, Verifier},
            Signature, SigningKey, VerifyingKey,
        };

        // Signing
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let message = b".well-known";
        let signature: Signature = signing_key.sign(message);

        // Verification
        let verify_key = VerifyingKey::from(&signing_key);
        assert!(verify_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn recover_ecdsa_sign() {
        use k256::ecdsa::{recoverable, signature::Signer, SigningKey};

        // Signing
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = signing_key.verifying_key();
        let message = b".well-known";
        let signature: recoverable::Signature = signing_key.sign(message);

        // Recovery
        let recovered_key = signature
            .recover_verify_key(message)
            .expect("couldn't recover pubkey");
        assert_eq!(&verify_key, &recovered_key);
    }
}
