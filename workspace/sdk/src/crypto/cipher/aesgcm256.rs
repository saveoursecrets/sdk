//! Encrypt and decrypt using 256 bit AES GSM.
use crate::crypto::{AeadPack, Cipher, DerivedPrivateKey, Nonce};
use crate::{Error, Result};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};

/// Encrypt plaintext using the given key as 256 bit AES-GCM.
///
/// If a nonce is not given a random nonce is generated.
pub async fn encrypt(
    cipher: &Cipher,
    key: &DerivedPrivateKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    assert!(matches!(cipher, Cipher::AesGcm256));

    std::thread::scope(move |s| {
        let handle = s.spawn(move || {
            let nonce = nonce.unwrap_or_else(Nonce::new_random_12);
            let cipher_nonce = AesNonce::from_slice(nonce.as_ref());
            let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
            let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
            Ok(AeadPack { ciphertext, nonce })
        });
        handle.join().unwrap()
    })
}

/// Decrypt ciphertext using the given key as 256 bit AES-GCM.
pub async fn decrypt(
    cipher: &Cipher,
    key: &DerivedPrivateKey,
    aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    assert!(matches!(cipher, Cipher::AesGcm256));

    std::thread::scope(move |s| {
        let handle = s.spawn(move || {
            if let Nonce::Nonce12(ref nonce) = aead_pack.nonce {
                let cipher_nonce = AesNonce::from_slice(nonce);
                let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
                Ok(cipher
                    .decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
            } else {
                Err(Error::InvalidNonce)
            }
        });
        handle.join().unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, DerivedPrivateKey};
    use anyhow::Result;

    #[tokio::test]
    async fn aesgcm256_encrypt_decrypt() -> Result<()> {
        let key = DerivedPrivateKey::generate();
        let plaintext = b"super secret value";
        let aead_pack =
            encrypt(&Cipher::AesGcm256, &key, plaintext, None).await?;
        let decrypted = decrypt(&Cipher::AesGcm256, &key, &aead_pack).await?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
