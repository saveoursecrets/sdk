use anyhow::Result;
use k256::ecdsa::{hazmat::SignPrimitive, SigningKey, VerifyingKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use sos_sdk::crypto::{csprng, Cipher, DerivedPrivateKey, PrivateKey};

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

#[test]
fn ecdsa_sign() -> Result<()> {
    // Generate a signature with recovery id
    let signing_key = SigningKey::random(&mut csprng());
    let message = b".well-known";
    let digest = Keccak256::digest(message);
    let (_signature, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<Sha256>(
            digest.as_slice().into(),
            b"",
        )?;
    assert!(recid.is_some());
    Ok(())
}

#[test]
fn ecdsa_sign_recover() -> Result<()> {
    let signing_key = SigningKey::random(&mut csprng());
    let message = b".well-known";
    let digest = Keccak256::digest(message);
    let (signature, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<Sha256>(
            digest.as_slice().into(),
            b"",
        )?;

    let verify_key = signing_key.verifying_key();

    // Recovery
    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(message),
        &signature,
        recid.unwrap(),
    )?;

    assert_eq!(verify_key, &recovered_key);
    Ok(())
}
