//! Encrypt and decrypt using XChacha20poly1305.
use crate::crypto::{AeadPack, DerivedPrivateKey, Nonce};
use crate::{Error, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

/// Encrypt plaintext as XChaCha20Poly1305 to an AeadPack.
///
/// If a nonce is not given a random nonce is generated.
pub fn encrypt(
    key: &DerivedPrivateKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    let nonce = nonce.unwrap_or_else(Nonce::new_random_24);
    let cipher_nonce = XNonce::from_slice(nonce.as_ref());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack { ciphertext, nonce })
}

/// Decrypt ciphertext using XChaCha20Poly1305.
pub fn decrypt(
    key: &DerivedPrivateKey,
    aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    if let Nonce::Nonce24(ref nonce) = aead_pack.nonce {
        let cipher_nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
    } else {
        Err(Error::InvalidNonce)
    }
}
