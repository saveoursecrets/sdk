//! File system paths and encrypted file storage.
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

use crate::{
    constants::{
        AUDIT_FILE_NAME, DEVICES_DIR, EVENT_LOG_EXT, FILES_DIR, IDENTITY_DIR,
        LOCAL_DIR, TEMP_DIR, TRASH_DIR, VAULTS_DIR, VAULT_EXT,
    },
    vfs,
};

mod app;
mod external_files;
mod user;

pub use app::AppPaths;
pub use external_files::{EncryptedFile, FileStorage};
pub use user::UserPaths;

/// Compute the file name from a path.
///
/// If no file name is available the returned value is the
/// empty string.
pub fn basename<P: AsRef<Path>>(path: P) -> String {
    path.as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Guess the MIME type of a path.
///
/// This implementation supports some more types
/// that are not in the the mime_guess library that
/// we also want to recognize.
pub fn guess_mime<P: AsRef<Path>>(path: P) -> Result<String> {
    if let Some(extension) = path.as_ref().extension() {
        let fixed = match extension.to_string_lossy().as_ref() {
            "heic" => Some("image/heic".to_string()),
            "heif" => Some("image/heif".to_string()),
            "avif" => Some("image/avif".to_string()),
            _ => None,
        };

        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
    }
    let mime = mime_guess::from_path(&path)
        .first_or(mime_guess::mime::APPLICATION_OCTET_STREAM)
        .to_string();
    Ok(mime)
}
