//! Encrypt and decrypt using 256 bit AES GSM.
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce,
};
use rand::Rng;

use super::AeadPack;
use crate::Result;

/// Encrypt plaintext using the key as 256 bit AES-GCM.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<AeadPack<12>> {
    // 96 bit (12 byte) unique nonce per message
    let nonce: [u8; 12] = rand::thread_rng().gen();
    let cipher_nonce = Nonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key));
    let ciphertext = cipher.encrypt(cipher_nonce, plaintext)?;
    Ok(AeadPack { ciphertext, nonce })
}

/// Decrypt ciphertext/nonce using the key as 256 bit AES-GCM.
pub fn decrypt(key: &[u8; 32], aead_pack: &AeadPack<12>) -> Result<Vec<u8>> {
    let cipher_nonce = Nonce::from_slice(&aead_pack.nonce);
    let cipher = Aes256Gcm::new(aes_gcm::Key::from_slice(key));
    Ok(cipher.decrypt(cipher_nonce, aead_pack.ciphertext.as_ref())?)
}
