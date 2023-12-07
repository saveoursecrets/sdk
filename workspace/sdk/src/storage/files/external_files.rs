//! Manages encryption and decryption for files.
//!
//! Also responsible for reading and writing external
//! file references to disc.
//!
//! Secrets of type file store the file data externally for
//! performance reasons and reference the external files
//! by vault identifier, secret identifier and file name.
//!
//! The file name is the hex-encoded digest of the encrypted data
//! stored on disc.

use crate::{
    vault::{secret::SecretId, VaultId},
    vfs::{self, File},
    Error, Paths, Result,
};
use age::Encryptor;
use futures::io::AsyncReadExt;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

use super::EncryptedFile;

/// Manage encrypted file storage.
pub struct FileStorage;

impl FileStorage {
    /// Encrypt a file using AGE passphrase encryption and
    /// write to a target directory returning an SHA256 digest
    /// of the encrypted data.
    ///
    /// The file name is the Sha256 digest of the encrypted data
    /// encoded to hexdecimal.
    pub async fn encrypt_file_passphrase<S: AsRef<Path>, T: AsRef<Path>>(
        input: S,
        target: T,
        passphrase: SecretString,
    ) -> Result<(Vec<u8>, u64)> {
        let file = File::open(input.as_ref()).await?;
        let encryptor = Encryptor::with_user_passphrase(passphrase);

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_async_output(&mut encrypted).await?;
        futures::io::copy(&mut file.compat(), &mut writer).await?;
        writer.finish()?;

        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        let digest = hasher.finalize();
        let file_name = hex::encode(digest);
        let dest = PathBuf::from(target.as_ref()).join(file_name);
        let size = encrypted.len() as u64;

        vfs::write(dest, encrypted).await?;

        Ok((digest.to_vec(), size))
    }

    /// Decrypt a file using AGE passphrase encryption.
    pub async fn decrypt_file_passphrase<P: AsRef<Path>>(
        input: P,
        passphrase: &SecretString,
    ) -> Result<Vec<u8>> {
        let mut file = File::open(input.as_ref()).await?.compat();
        let decryptor = match age::Decryptor::new_async(&mut file).await? {
            age::Decryptor::Passphrase(d) => d,
            _ => return Err(Error::NotPassphraseEncryption),
        };

        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt_async(passphrase, None)?;
        reader.read_to_end(&mut decrypted).await?;
        Ok(decrypted)
    }

    /// Encrypt a file and write it to the external
    /// file storage location.
    ///
    /// Returns an SHA256 digest of the encrypted data
    /// and the size of the original file.
    pub async fn encrypt_file_storage<P: AsRef<Path>>(
        password: SecretString,
        path: P,
        paths: &Paths,
        vault_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<EncryptedFile> {
        let target = paths
            .files_dir()
            .join(vault_id.to_string())
            .join(secret_id.to_string());

        if !vfs::try_exists(&target).await? {
            vfs::create_dir_all(&target).await?;
        }

        // Encrypt the file and write it to the storage location
        let (digest, size) =
            Self::encrypt_file_passphrase(path, target, password).await?;
        Ok(EncryptedFile { digest, size })
    }

    /// Decrypt a file in the storage location and return the buffer.
    pub async fn decrypt_file_storage(
        password: &SecretString,
        paths: &Paths,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: impl AsRef<str>,
    ) -> Result<Vec<u8>> {
        let path = paths.file_location(vault_id, secret_id, file_name);
        Self::decrypt_file_passphrase(path, password).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{passwd::diceware::generate_passphrase, vfs};
    use anyhow::Result;

    #[tokio::test]
    async fn file_encrypt_decrypt() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let input = "../../tests/fixtures/sample.heic";
        let output = "target/file-encrypt-decrypt";

        if let Ok(true) = vfs::try_exists(output).await {
            vfs::remove_dir_all(output).await?;
        }

        vfs::create_dir_all(output).await?;

        let encrypted = FileStorage::encrypt_file_passphrase(
            input,
            output,
            passphrase.clone(),
        )
        .await?;

        let target = PathBuf::from(output).join(hex::encode(encrypted.0));
        let decrypted =
            FileStorage::decrypt_file_passphrase(target, &passphrase).await?;

        let contents = vfs::read(input).await?;
        assert_eq!(contents, decrypted);
        Ok(())
    }
}
