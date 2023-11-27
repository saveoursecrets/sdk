//! File encryption/decryption and manager for external files.
mod external_files;
mod external_files_sync;
mod file_manager;

pub use external_files::FileStorage;
pub use external_files_sync::FileStorageSync;
pub use file_manager::{FileProgress, FileSource};

/// Meta data about an encrypted file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}
