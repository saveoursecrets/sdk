use anyhow::Result;
use sos_core::crypto::cipher::x25519::{decrypt, encrypt};

#[tokio::test]
async fn x25519_encrypt_decrypt() -> Result<()> {
    let user_1 = age::x25519::Identity::generate();
    let user_2 = age::x25519::Identity::generate();

    let pub_1 = user_1.to_public();
    let pub_2 = user_2.to_public();

    let recipients = vec![pub_1, pub_2];
    let plaintext = b"super secret value";
    let aead = encrypt(plaintext, recipients).await?;

    let plain_1 = decrypt(&user_1, &aead).await?;
    assert_eq!(plaintext.as_slice(), &plain_1);

    let plain_2 = decrypt(&user_2, &aead).await?;
    assert_eq!(plaintext.as_slice(), &plain_2);

    Ok(())
}
