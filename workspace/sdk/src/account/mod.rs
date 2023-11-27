//! Create and manage local accounts.
mod account_manager;
pub mod archive;
mod builder;
pub mod files;
mod identity;
mod local;
mod login;
mod passphrase;
mod paths;
mod provider;
pub mod search;

#[cfg(feature = "security-report")]
pub mod security_report;

#[cfg(feature = "contacts")]
pub use account_manager::ContactImportProgress;

pub use account_manager::{
    Account, AccountData, AccountHandler, DetachedView, SecretOptions,
    UserStatistics,
};
pub use builder::{AccountBuilder, CreatedAccount, NewAccount};
pub use identity::{AccountStatus, Identity};
pub use local::{AccountInfo, AccountRef, LocalAccounts};
pub use login::{AuthenticatedUser, DeviceSigner};
pub use passphrase::DelegatedPassphrase;
pub use paths::UserPaths;
pub use provider::{LocalProvider, LocalState};

use crate::Result;
use std::path::Path;

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
