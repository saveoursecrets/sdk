//! File encryption/decryption and manager for external files.
mod external_files;
mod file_manager;

pub use external_files::FileStorage;
pub use file_manager::{FileMutationEvent, FileProgress, FileSource};

/// Meta data about an encrypted file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}
