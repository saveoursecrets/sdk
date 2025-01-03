//! Encrypt and decrypt using 256 bit AES GSM.
use crate::crypto::{AeadPack, DerivedPrivateKey, Nonce};
use crate::{Error, Result};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};

/// Encrypt plaintext using the given key as 256 bit AES-GCM.
///
/// If a nonce is not given a random nonce is generated.
pub fn encrypt(
    key: &DerivedPrivateKey,
    plaintext: &[u8],
    nonce: Option<Nonce>,
) -> Result<AeadPack> {
    let nonce = nonce.unwrap_or_else(Nonce::new_random_12);
    let cipher_nonce = AesNonce::from_slice(nonce.as_ref());
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack { ciphertext, nonce })
}

/// Decrypt ciphertext using the given key as 256 bit AES-GCM.
pub fn decrypt(
    key: &DerivedPrivateKey,
    aead_pack: &AeadPack,
) -> Result<Vec<u8>> {
    if let Nonce::Nonce12(ref nonce) = aead_pack.nonce {
        let cipher_nonce = AesNonce::from_slice(nonce);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
        Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
    } else {
        Err(Error::InvalidNonce)
    }
}
