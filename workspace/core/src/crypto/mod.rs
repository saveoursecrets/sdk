//! Cryptographic routines and types.
use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
};

pub mod aes_gcm_256;
pub mod authorize;
pub mod xchacha20poly1305;
pub mod keypair;
pub mod passphrase;

/// Type identifiers for ECDSA keys.
pub mod types {
    /// Represents the k256 (secp256k1) single party key.
    pub const K256: u8 = 0x01;
}

/// Encrypted data with the nonce.
#[derive(Debug, Eq, PartialEq)]
pub struct AeadPack<const SIZE: usize> {
    /// Number once value.
    pub nonce: [u8; SIZE],
    /// Encrypted cipher text.
    pub ciphertext: Vec<u8>,
}

impl Default for AeadPack<12> {
    fn default() -> Self {
        Self {
            nonce: [0; 12],
            ciphertext: Default::default(),
        }
    }
}

impl Default for AeadPack<24> {
    fn default() -> Self {
        Self {
            nonce: [0; 24],
            ciphertext: Default::default(),
        }
    }
}

impl Encode for AeadPack<12> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&self.nonce)?;
        self.ciphertext.serialize(ser)?;
        Ok(())
    }
}

impl Decode for AeadPack<12> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.nonce = de.reader.read_bytes(12)?.as_slice().try_into()?;
        self.ciphertext = Deserialize::deserialize(de)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::aes_gcm_256::*;
    use anyhow::Result;

    #[test]
    fn aes_gcm_encrypt_decrypt() -> Result<()> {
        // Key must be 32 bytes
        let key = b"an example very very secret key.";
        let value = b"plaintext message";
        let aead = encrypt(key, value)?;
        let plaintext = decrypt(key, &aead)?;
        assert_eq!(&plaintext, value);
        Ok(())
    }

    #[test]
    fn aes_gcm_encrypt_decrypt_tamper() -> () {
        // Key must be 32 bytes
        let key = b"an example very very secret key.";
        let value = b"plaintext message";
        let mut aead = encrypt(key, value).unwrap();

        // Flip all the bits
        aead.ciphertext = aead.ciphertext.iter().map(|b| !*b).collect();

        // Fails due to tampering
        assert!(decrypt(key, &aead).is_err());
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
