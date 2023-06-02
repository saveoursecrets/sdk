//! Encrypt and decrypt using XChacha20poly1305.
use crate::crypto::{AeadPack, Cipher, DerivedPrivateKey, Nonce};
use crate::{Error, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

/// Encrypt plaintext as XChaCha20Poly1305 to an AeadPack.
///
/// If a nonce is not given a random nonce is generated.
pub async fn encrypt(
    cipher: &Cipher,
    key: &DerivedPrivateKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    assert!(matches!(cipher, Cipher::XChaCha20Poly1305));

    std::thread::scope(move |s| {
        let handle = s.spawn(move || {
            let nonce = nonce.unwrap_or_else(Nonce::new_random_24);
            let cipher_nonce = XNonce::from_slice(nonce.as_ref());
            let cipher =
                XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
            let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
            Ok(AeadPack { ciphertext, nonce })
        });
        handle.join().unwrap()
    })
}

/// Decrypt ciphertext using XChaCha20Poly1305.
pub async fn decrypt(
    cipher: &Cipher,
    key: &DerivedPrivateKey,
    aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    assert!(matches!(cipher, Cipher::XChaCha20Poly1305));

    std::thread::scope(move |s| {
        let handle = s.spawn(move || {
            if let Nonce::Nonce24(ref nonce) = aead_pack.nonce {
                let cipher_nonce = XNonce::from_slice(nonce);
                let cipher =
                    XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
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
    async fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
        let key = DerivedPrivateKey::generate();
        let plaintext = b"super secret value";
        let aead_pack =
            encrypt(&Cipher::XChaCha20Poly1305, &key, plaintext, None)
                .await?;
        let decrypted =
            decrypt(&Cipher::XChaCha20Poly1305, &key, &aead_pack).await?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
