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

use age::Encryptor;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

use crate::{storage::StorageDirs, Error, Result};

/// Result of encrypting a file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}

/// Manage encrypted file storage.
pub struct FileStorage;

impl FileStorage {
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn encrypt_file_storage<
        P: AsRef<Path>,
        A: AsRef<Path>,
        V: AsRef<Path>,
        S: AsRef<Path>,
    >(
        password: SecretString,
        path: P,
        address: A,
        vault_id: V,
        secret_id: S,
    ) -> Result<EncryptedFile> {
        let target = StorageDirs::files_dir(address)?
            .join(vault_id)
            .join(secret_id);

        if !target.exists() {
            std::fs::create_dir_all(&target)?;
        }

        // Encrypt the file and write it to the storage location
        let (digest, size) =
            Self::encrypt_file_passphrase(path, target, password)?;
        Ok(EncryptedFile { digest, size })
    }

    /// Decrypt a file in the storage location and return the buffer.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt_file_storage<
        A: AsRef<Path>,
        V: AsRef<Path>,
        S: AsRef<Path>,
        F: AsRef<Path>,
    >(
        password: &SecretString,
        address: A,
        vault_id: V,
        secret_id: S,
        file_name: F,
    ) -> Result<Vec<u8>> {
        let path = StorageDirs::file_location(
            address, vault_id, secret_id, file_name,
        )?;
        Self::decrypt_file_passphrase(path, password)
    }
}
