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

use crate::Result;
use age::Encryptor;
use futures::io::{AsyncReadExt, BufReader};
use hex;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use sos_core::{ExternalFileName, Paths, VaultId};
use sos_external_files::EncryptedFile;
use sos_filesystem::write_exclusive;
use sos_vault::secret::SecretId;
use sos_vfs::{self as vfs, File};
use std::path::{Path, PathBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

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

        write_exclusive(dest, encrypted).await?;

        Ok((digest.to_vec(), size))
    }

    /// Decrypt a file using AGE passphrase encryption.
    pub async fn decrypt_file_passphrase<P: AsRef<Path>>(
        input: P,
        passphrase: &SecretString,
    ) -> Result<Vec<u8>> {
        let mut file =
            BufReader::new(File::open(input.as_ref()).await?.compat());
        let decryptor = age::Decryptor::new_async_buffered(&mut file).await?;

        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt_async(std::iter::once(
            &age::scrypt::Identity::new(passphrase.clone()) as _,
        ))?;
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
        let target = paths.into_file_secret_path(vault_id, secret_id);
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
        file_name: &ExternalFileName,
    ) -> Result<Vec<u8>> {
        let path = paths.into_file_path_parts(vault_id, secret_id, file_name);
        Self::decrypt_file_passphrase(path, password).await
    }
}
