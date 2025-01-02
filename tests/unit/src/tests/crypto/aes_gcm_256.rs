use anyhow::Result;
use sos_sdk::crypto::{
    cipher::aes_gcm_256::{decrypt, encrypt},
    DerivedPrivateKey,
};

#[test]
fn aes_gcm_256_encrypt_decrypt() -> Result<()> {
    let key = DerivedPrivateKey::generate();
    let plaintext = b"super secret value";
    let aead_pack = encrypt(&key, plaintext, None)?;
    let decrypted = decrypt(&key, &aead_pack)?;
    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
