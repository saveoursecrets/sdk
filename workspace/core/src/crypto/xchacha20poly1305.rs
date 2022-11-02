//! Encrypt and decrypt using XChacha20poly1305.
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

use super::{secret_key::SecretKey, AeadPack, Nonce};
use crate::{Error, Result};

/// Encrypt plaintext as XChaCha20Poly1305 to an AeadPack.
pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    let nonce = nonce.unwrap_or_else(|| Nonce::new_random_24());
    let cipher_nonce = XNonce::from_slice(nonce.as_ref());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack { ciphertext, nonce })
}

/// Decrypt ciphertext using XChaCha20Poly1305.
pub fn decrypt(key: &SecretKey, aead_pack: &AeadPack) -> Result<Vec<u8>> {
    if let Nonce::Nonce24(ref nonce) = aead_pack.nonce {
        let cipher_nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
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
    fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
        let key = SecretKey::new_random_32();
        let plaintext = b"super secret value";
        let aead_pack = encrypt(&key, plaintext, None)?;
        let decrypted = decrypt(&key, &aead_pack)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
