//! Encrypt and decrypt using 256 bit AES GSM.
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};

use super::{secret_key::SecretKey, AeadPack, Nonce};
use crate::{Error, Result};

/// Encrypt plaintext using the given key as 256 bit AES-GCM.
pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    // 96 bit (12 byte) unique nonce per message
    let nonce = nonce.unwrap_or_else(Nonce::new_random_12);
    let cipher_nonce = AesNonce::from_slice(nonce.as_ref());
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack { ciphertext, nonce })
}

/// Decrypt ciphertext using the given key as 256 bit AES-GCM.
pub fn decrypt(key: &SecretKey, aead_pack: &AeadPack) -> Result<Vec<u8>> {
    if let Nonce::Nonce12(ref nonce) = aead_pack.nonce {
        let cipher_nonce = AesNonce::from_slice(nonce);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
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

    #[test]
    fn aesgcm256_encrypt_decrypt() -> Result<()> {
        let key = SecretKey::new_random_32();
        let plaintext = b"super secret value";
        let aead_pack = encrypt(&key, plaintext, None)?;
        let decrypted = decrypt(&key, &aead_pack)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
