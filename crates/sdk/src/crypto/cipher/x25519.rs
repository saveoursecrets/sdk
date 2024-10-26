//! Encrypt and decrypt using X25519 asymmetric encryption (AGE).
use crate::crypto::{AeadPack, Cipher, Nonce};
use crate::{Error, Result};
use age::x25519::{Identity, Recipient};
use futures::io::{AsyncReadExt, BufReader};

/// Encrypt plaintext as X25519 to an AeadPack.
pub async fn encrypt(
    cipher: &Cipher,
    plaintext: &[u8],
    recipients: Vec<Recipient>,
) -> Result<AeadPack> {
    if let Cipher::X25519 = cipher {
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
    } else {
        let expected = Cipher::X25519;
        Err(Error::BadCipher(expected.to_string(), cipher.to_string()))
    }
}

/// Decrypt ciphertext using X25519.
pub async fn decrypt(
    cipher: &Cipher,
    identity: &Identity,
    aead: &AeadPack,
) -> Result<Vec<u8>> {
    if let Cipher::X25519 = cipher {
        let mut reader = BufReader::new(aead.ciphertext.as_slice());
        let decryptor =
            age::Decryptor::new_async_buffered(&mut reader).await?;

        let mut plaintext = vec![];
        let mut reader = decryptor
            .decrypt_async(std::iter::once(identity as &dyn age::Identity))?;
        reader.read_to_end(&mut plaintext).await?;
        Ok(plaintext)
    } else {
        let expected = Cipher::X25519;
        Err(Error::BadCipher(expected.to_string(), cipher.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn x25519_encrypt_decrypt() -> Result<()> {
        let user_1 = age::x25519::Identity::generate();
        let user_2 = age::x25519::Identity::generate();

        let pub_1 = user_1.to_public();
        let pub_2 = user_2.to_public();

        let recipients = vec![pub_1, pub_2];
        let cipher = Cipher::X25519;
        let plaintext = b"super secret value";
        let aead = encrypt(&cipher, plaintext, recipients).await?;

        let plain_1 = decrypt(&cipher, &user_1, &aead).await?;
        assert_eq!(plaintext.as_slice(), &plain_1);

        let plain_2 = decrypt(&cipher, &user_2, &aead).await?;
        assert_eq!(plaintext.as_slice(), &plain_2);

        Ok(())
    }
}
