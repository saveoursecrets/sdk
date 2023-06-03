//! Encrypt and decrypt using X25519 asymmetric encryption (AGE).
use crate::crypto::{AeadPack, Cipher, Nonce, PrivateKey};
use crate::Result;

/// Encrypt plaintext as X25519 to an AeadPack.
pub async fn encrypt(
    cipher: &Cipher,
    _key: &PrivateKey,
    _plaintext: &[u8],
    _nonce: Option<Nonce>,
) -> Result<AeadPack> {
    assert!(matches!(cipher, Cipher::X25519(_)));
    todo!();
}

/// Decrypt ciphertext using X25519.
pub async fn decrypt(
    cipher: &Cipher,
    _key: &PrivateKey,
    _aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    assert!(matches!(cipher, Cipher::X25519(_)));
    todo!();
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
