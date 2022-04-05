//! Encrypt and decrypt using XChacha20poly1305.
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use rand::Rng;

use super::{AeadPack, Nonce};
use crate::{Error, Result};

/// Encrypt plaintext as XChaCha20Poly1305 to an AeadPack.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<AeadPack> {
    let nonce: [u8; 24] = rand::thread_rng().gen();
    let cipher_nonce = XNonce::from_slice(&nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack {
        ciphertext,
        nonce: Nonce::Nonce24(nonce),
    })
}

/// Decrypt an AeadPack using XChaCha20Poly1305.
pub fn decrypt(key: &[u8; 32], aead_pack: &AeadPack) -> Result<Vec<u8>> {
    if let Nonce::Nonce24(ref nonce) = aead_pack.nonce {
        let cipher_nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
    } else {
        Err(Error::InvalidNonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rand::Rng;

    #[test]
    fn xchacha20poly1305_encrypt_decrypt() -> Result<()> {
        let key: [u8; 32] = rand::thread_rng().gen();
        let plaintext = b"super secret value";
        let aead_pack = encrypt(&key, plaintext)?;
        let decrypted = decrypt(&key, &aead_pack)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }
}
