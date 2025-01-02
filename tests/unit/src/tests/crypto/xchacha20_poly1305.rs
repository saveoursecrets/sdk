use anyhow::Result;
use sos_sdk::crypto::{
    cipher::xchacha20_poly1305::{decrypt, encrypt},
    DerivedPrivateKey,
};

#[test]
fn xchacha20_poly1305_encrypt_decrypt() -> Result<()> {
    let key = DerivedPrivateKey::generate();
    let plaintext = b"super secret value";
    let aead_pack = encrypt(&key, plaintext, None)?;
    let decrypted = decrypt(&key, &aead_pack)?;
    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
