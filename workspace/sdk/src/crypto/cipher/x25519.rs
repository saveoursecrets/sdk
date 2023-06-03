//! Encrypt and decrypt using X25519 asymmetric encryption (AGE).
use crate::crypto::{AeadPack, Cipher, Nonce, PrivateKey};
use crate::Result;

/// Encrypt plaintext as XChaCha20Poly1305 to an AeadPack.
///
/// If a nonce is not given a random nonce is generated.
pub async fn encrypt(
    cipher: &Cipher,
    _key: &PrivateKey,
    _plaintext: &[u8],
    _nonce: Option<Nonce>,
) -> Result<AeadPack> {
    assert!(matches!(cipher, Cipher::X25519(_)));
    todo!();

    /*
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
    */
}

/// Decrypt ciphertext using XChaCha20Poly1305.
pub async fn decrypt(
    cipher: &Cipher,
    _key: &PrivateKey,
    _aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    assert!(matches!(cipher, Cipher::X25519(_)));
    todo!();

    /*
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
    */
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    #[tokio::test]
    async fn x25519_encrypt_decrypt() -> Result<()> {
        /*
        let key = DerivedPrivateKey::generate();
        let plaintext = b"super secret value";
        let recipients = Vec::new();
        let aead_pack = encrypt(Cipher::X25519(recipients.clone()), &key, plaintext, None).await?;
        let decrypted = decrypt(Cipher::X25519(recipients.clone()), &key, &aead_pack).await?;
        assert_eq!(plaintext.to_vec(), decrypted);
        */

        Ok(())
    }
}
