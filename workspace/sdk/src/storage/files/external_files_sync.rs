//! Sync workaround for the futures::io::copy() bug.
//!
//! Hopefully one day we can remove this and use the newer FileStorage
//! which works fine when executing natively but not when executed
//! via flutter_rust_bridge.

// SEE: https://github.com/fzyzcjy/flutter_rust_bridge/discussions/1267

use age::Encryptor;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    vault::{secret::SecretId, VaultId},
    Error, Paths, Result,
};

use super::EncryptedFile;

/// Manage encrypted file storage.
#[doc(hidden)]
pub struct FileStorageSync;

impl FileStorageSync {
    /// Encrypt a file using AGE passphrase encryption and
    /// write to a target directory returning an SHA256 digest
    /// of the encrypted data.
    ///
    /// The file name is the Sha256 digest of the encrypted data
    /// encoded to hexdecimal.
    pub fn encrypt_file_passphrase<S: AsRef<Path>, T: AsRef<Path>>(
        source: S,
        target: T,
        passphrase: SecretString,
    ) -> Result<(Vec<u8>, u64)> {
        let mut file = std::fs::File::open(source)?;
        let encryptor = Encryptor::with_user_passphrase(passphrase);

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        std::io::copy(&mut file, &mut writer)?;
        writer.finish()?;

        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        let digest = hasher.finalize();
        let file_name = hex::encode(digest);
        let dest = PathBuf::from(target.as_ref()).join(file_name);
        let size = encrypted.len() as u64;

        std::fs::write(dest, encrypted)?;

        Ok((digest.to_vec(), size))
    }

    /// Decrypt a file using AGE passphrase encryption.
    pub fn decrypt_file_passphrase<P: AsRef<Path>>(
        path: P,
        passphrase: &SecretString,
    ) -> Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let decryptor = match age::Decryptor::new(file)? {
            age::Decryptor::Passphrase(d) => d,
            _ => return Err(Error::NotPassphraseEncryption),
        };

        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt(passphrase, None)?;
        reader.read_to_end(&mut decrypted)?;

        Ok(decrypted)
    }

    /// Encrypt a file and write it to the external
    /// file storage location.
    ///
    /// Returns an SHA256 digest of the encrypted data
    /// and the size of the original file.
    pub fn encrypt_file_storage<P: AsRef<Path>>(
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

        if !target.exists() {
            std::fs::create_dir_all(&target)?;
        }

        // Encrypt the file and write it to the storage location
        let (digest, size) =
            Self::encrypt_file_passphrase(path, target, password)?;
        Ok(EncryptedFile { digest, size })
    }

    /// Decrypt a file in the storage location and return the buffer.
    pub fn decrypt_file_storage(
        password: &SecretString,
        paths: &Paths,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: impl AsRef<str>,
    ) -> Result<Vec<u8>> {
        let path = paths.file_location(vault_id, secret_id, file_name);
        Self::decrypt_file_passphrase(path, password)
    }
}
