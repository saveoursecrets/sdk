//! Encrypt and decrypt using 256 bit AES GSM.
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::Rng;

use super::{AeadPack, Nonce};
use crate::{Error, Result};

/// Encrypt plaintext using the key as 256 bit AES-GCM.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<AeadPack> {
    // 96 bit (12 byte) unique nonce per message
    let nonce: [u8; 12] = rand::thread_rng().gen();
    let cipher_nonce = AesNonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack {
        ciphertext,
        nonce: Nonce::Nonce12(nonce),
    })
}

/// Decrypt ciphertext/nonce using the key as 256 bit AES-GCM.
pub fn decrypt(key: &[u8; 32], aead_pack: &AeadPack) -> Result<Vec<u8>> {
    if let Nonce::Nonce12(ref nonce) = aead_pack.nonce {
        let cipher_nonce = AesNonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key));
        Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
    } else {
        Err(Error::InvalidNonce)
    }
}
