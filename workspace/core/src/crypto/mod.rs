//! Cryptographic routines and types.
use crate::Error;
use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};

pub mod aesgcm256;
pub mod authorize;
pub mod keypair;
pub mod secret_key;
pub mod xchacha20poly1305;

/// Constants for supported symmetric ciphers.
pub mod algorithms {
    use crate::Error;
    use serde_binary::{
        Decode, Deserializer, Encode, Error as BinaryError,
        Result as BinaryResult, Serializer,
    };
    use std::convert::AsRef;
    use std::str::FromStr;

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
        fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
            ser.writer.write_u8(*self.as_ref())?;
            Ok(())
        }
    }

    impl Decode for Algorithm {
        fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
            let id = de.reader.read_u8()?;
            *self = match id {
                X_CHACHA20_POLY1305 => Algorithm::XChaCha20Poly1305(id),
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

/// Type identifiers for ECDSA keys.
pub mod types {
    /// Represents the k256 (secp256k1) single party key.
    pub const K256: u8 = 0x01;
}

/// Enumeration of the sizes for nonces.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum Nonce {
    /// Standard 12 byte nonce used by AES-GCM and ChaCha20Poly1305.
    Nonce12([u8; 12]),
    /// Extended 24 byte nonce used by XChaCha20Poly1305.
    Nonce24([u8; 24]),
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce::Nonce24([0; 24])
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
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        match &self.nonce {
            Nonce::Nonce12(ref bytes) => {
                ser.writer.write_u8(12)?;
                ser.writer.write_bytes(bytes)?;
            }
            Nonce::Nonce24(ref bytes) => {
                ser.writer.write_u8(24)?;
                ser.writer.write_bytes(bytes)?;
            }
        }
        self.ciphertext.serialize(ser)?;
        Ok(())
    }
}

impl Decode for AeadPack {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let nonce_size = de.reader.read_u8()?;
        let nonce_buffer = de.reader.read_bytes(nonce_size as usize)?;
        match nonce_size {
            12 => {
                self.nonce = Nonce::Nonce12(nonce_buffer.as_slice().try_into()?)
            }
            24 => {
                self.nonce = Nonce::Nonce24(nonce_buffer.as_slice().try_into()?)
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownNonceSize(nonce_size),
                )));
            }
        }
        self.ciphertext = Deserialize::deserialize(de)?;
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
        let aead = encrypt(&key, value)?;
        let plaintext = decrypt(&key, &aead)?;
        assert_eq!(&plaintext, value);
        Ok(())
    }

    #[test]
    fn xchacha20poly1305_encrypt_decrypt_tamper() -> () {
        let key = SecretKey::new_random_32();
        let value = b"plaintext message";
        let mut aead = encrypt(&key, value).unwrap();

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

    #[test]
    fn auth_success() -> Result<()> {
        use super::authorize::*;

        use k256::ecdsa::{
            signature::{Signature as EcdsaSignature, Signer},
            Signature, SigningKey, VerifyingKey,
        };

        // In the real world only the client knows about the SigningKey
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = VerifyingKey::from(&signing_key);
        let public_key: PublicKey = verify_key.into();

        // List of allowed public keys would usually be extracted from
        // the vault file header
        let public_keys = vec![public_key];

        // Server generates a challenge for the client
        let mut authorization: Authorization = Default::default();
        let challenge = Challenge::new("mock".to_string());
        let server_packet = serde_json::to_string(&challenge)?;
        authorization.add(challenge);

        // ... server sends challenge to client

        // Client receives the challenge
        let client_challenge: Challenge = serde_json::from_str(&server_packet)?;
        let client_signature: Signature =
            signing_key.sign(client_challenge.message());
        let signature_bytes = client_signature.as_bytes().to_vec();
        let client_response = ChallengeResponse::new(
            client_challenge.id().clone(),
            signature_bytes,
        );
        let client_packet = serde_json::to_string(&client_response)?;

        // ... client sends the response to the server

        // Server receives the response
        let challenge_response: ChallengeResponse =
            serde_json::from_str(&client_packet)?;

        assert!(authorization
            .authorize(&public_keys, &challenge_response)
            .is_ok());

        Ok(())
    }
}
