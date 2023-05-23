//! Cryptographic routines and types.
use crate::Error;
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, Write};

pub mod aesgcm256;
mod algorithms;
pub mod channel;
pub mod secret_key;
pub mod xchacha20poly1305;

pub use algorithms::*;

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
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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

    use k256::ecdsa::{hazmat::SignPrimitive, SigningKey, VerifyingKey};
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};

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
    fn ecdsa_sign() -> Result<()> {
        // Generate a signature with recovery id
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let message = b".well-known";
        let digest = Keccak256::digest(message);
        let (_signature, recid) = signing_key
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<Sha256>(
                digest.as_slice().into(),
                b"",
            )?;
        assert!(recid.is_some());
        Ok(())
    }

    #[test]
    fn ecdsa_sign_recover() -> Result<()> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let message = b".well-known";
        let digest = Keccak256::digest(message);
        let (signature, recid) = signing_key
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<Sha256>(
                digest.as_slice().into(),
                b"",
            )?;

        let verify_key = signing_key.verifying_key();

        // Recovery
        let recovered_key = VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(message),
            &signature,
            recid.unwrap(),
        )?;

        assert_eq!(verify_key, &recovered_key);
        Ok(())
    }
}
