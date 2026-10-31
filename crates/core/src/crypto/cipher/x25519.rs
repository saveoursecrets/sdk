//! Encrypt and decrypt using X25519 asymmetric encryption (AGE).
use crate::Result;
use crate::crypto::{AeadPack, Nonce};
use age::x25519::{Identity, Recipient};
use futures::io::{AsyncReadExt, BufReader};

/// Encrypt plaintext as X25519 to an AeadPack.
pub async fn encrypt(
    plaintext: &[u8],
    recipients: Vec<Recipient>,
) -> Result<AeadPack> {
    debug_assert!(
        !recipients.is_empty(),
        "asymmetric encryption recipients must not be empty"
    );
    let recipients: Vec<_> = recipients
        .into_iter()
        .map(|r| {
            let r: Box<dyn age::Recipient + Send> = Box::new(r.clone());
            r
        })
        .collect();

    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| &**r as _),
    )?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_async_output(&mut ciphertext).await?;
    let mut reader = BufReader::new(plaintext);
    futures::io::copy(&mut reader, &mut writer).await?;
    writer.finish()?;
    Ok(AeadPack {
        ciphertext,
        nonce: Nonce::new_random_12(),
    })
}

/// Decrypt ciphertext using X25519.
pub async fn decrypt(
    identity: &Identity,
    aead: &AeadPack,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(aead.ciphertext.as_slice());
    let decryptor = age::Decryptor::new_async_buffered(&mut reader).await?;

    let mut plaintext = vec![];
    let mut reader = decryptor
        .decrypt_async(std::iter::once(identity as &dyn age::Identity))?;
    reader.read_to_end(&mut plaintext).await?;
    Ok(plaintext)
}
