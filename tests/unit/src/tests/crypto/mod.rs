use anyhow::Result;
use sos_sdk::crypto::{Cipher, DerivedPrivateKey, PrivateKey};

mod aes_gcm_256;
mod key_derivation;
mod x25519;
mod xchacha20_poly1305;

#[tokio::test]
async fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
    let cipher = Cipher::XChaCha20Poly1305;
    let key = PrivateKey::Symmetric(DerivedPrivateKey::generate());
    let value = b"plaintext message";
    let aead = cipher.encrypt_symmetric(&key, value, None).await?;
    let plaintext = cipher.decrypt_symmetric(&key, &aead).await?;
    assert_eq!(&plaintext, value);
    Ok(())
}

#[tokio::test]
async fn xchacha20poly1305_encrypt_decrypt_tamper() {
    let cipher = Cipher::XChaCha20Poly1305;
    let key = PrivateKey::Symmetric(DerivedPrivateKey::generate());
    let value = b"plaintext message";
    let mut aead = cipher.encrypt_symmetric(&key, value, None).await.unwrap();

    // Flip all the bits
    aead.ciphertext = aead.ciphertext.iter().map(|b| !*b).collect();

    // Fails due to tampering
    assert!(cipher.decrypt_symmetric(&key, &aead).await.is_err());
}
