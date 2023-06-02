//! Cryptographic routines and types.
use rand::{rngs::OsRng, CryptoRng, Rng};
use serde::{Deserialize, Serialize};

pub(crate) mod aesgcm256;
pub mod channel;
mod cipher;
mod key_derivation;
mod private_key;
pub(crate) mod xchacha20poly1305;

pub use cipher::Cipher;
pub(crate) use cipher::{AES_GCM_256, X_CHACHA20_POLY1305};

pub use key_derivation::{KeyDerivation, Seed};
pub(crate) use key_derivation::{
    Deriver, ARGON_2_ID, BALLOON_HASH, SEED_SIZE,
};

pub use private_key::DerivedPrivateKey;

/// Exposes the default cryptographically secure RNG.
pub fn csprng() -> impl CryptoRng + Rng {
    OsRng
}

/// Enumeration of the sizes for nonces.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub enum Nonce {
    /// Standard 12 byte nonce used by AES-GCM.
    Nonce12([u8; 12]),
    /// Extended 24 byte nonce used by XChaCha20Poly1305.
    Nonce24([u8; 24]),
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
#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq, Clone)]
pub struct AeadPack {
    /// Number once value.
    pub nonce: Nonce,
    /// Encrypted cipher text.
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::xchacha20poly1305::*;
    use crate::crypto::{csprng, DerivedPrivateKey};
    use anyhow::Result;

    use k256::ecdsa::{hazmat::SignPrimitive, SigningKey, VerifyingKey};
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};

    #[tokio::test]
    async fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
        let key = DerivedPrivateKey::generate();
        let value = b"plaintext message";
        let aead = encrypt(&key, value, None).await?;
        let plaintext = decrypt(&key, &aead).await?;
        assert_eq!(&plaintext, value);
        Ok(())
    }

    #[tokio::test]
    async fn xchacha20poly1305_encrypt_decrypt_tamper() {
        let key = DerivedPrivateKey::generate();
        let value = b"plaintext message";
        let mut aead = encrypt(&key, value, None).await.unwrap();

        // Flip all the bits
        aead.ciphertext = aead.ciphertext.iter().map(|b| !*b).collect();

        // Fails due to tampering
        assert!(decrypt(&key, &aead).await.is_err());
    }

    #[test]
    fn ecdsa_sign() -> Result<()> {
        // Generate a signature with recovery id
        let signing_key = SigningKey::random(&mut csprng());
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
        let signing_key = SigningKey::random(&mut csprng());
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
