//! Encrypt and decrypt using 256 bit AES GSM.
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::Rng;

use super::{secret_key::SecretKey, AeadPack, Nonce};
use crate::{Error, Result};

/// Encrypt plaintext using the given key as 256 bit AES-GCM.
pub fn encrypt(key: &SecretKey, plaintext: &[u8]) -> Result<AeadPack> {
    // 96 bit (12 byte) unique nonce per message
    let nonce: [u8; 12] = rand::thread_rng().gen();
    let cipher_nonce = AesNonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key.as_slice()));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack {
        ciphertext,
        nonce: Nonce::Nonce12(nonce),
    })
}

/// Decrypt ciphertext using the given key as 256 bit AES-GCM.
pub fn decrypt(key: &SecretKey, aead_pack: &AeadPack) -> Result<Vec<u8>> {
    if let Nonce::Nonce12(ref nonce) = aead_pack.nonce {
        let cipher_nonce = AesNonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key.as_slice()));
        Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
    } else {
        Err(Error::InvalidNonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret_key::SecretKey;
    use anyhow::Result;
    use rand::Rng;

    #[test]
    fn aesgcm256_encrypt_decrypt() -> Result<()> {
        let key = SecretKey::new_random_32();
        let plaintext = b"super secret value";
        let aead_pack = encrypt(&key, plaintext)?;
        let decrypted = decrypt(&key, &aead_pack)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
