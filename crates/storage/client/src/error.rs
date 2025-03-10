use sos_core::{AuthenticationError, ErrorExt, SecretId, VaultId};
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the client storage library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated attempting to make changes to the current
    /// vault but no vault is open.
    #[error("no vault is available, vault must be open")]
    NoOpenVault,

    /// Error generated when a directory is expected.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when a file secret is expected.
    #[error("not a file secret")]
    NotFileContent,

    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Error generated when a folder password in the identity
    /// vault could not be located.
    #[error("could not find folder password for '{0}'")]
    NoFolderPassword(VaultId),

    /// Error generated when a file encryption password is required.
    #[error("no file password")]
    NoFilePassword,

    /// Error generated when a secret could not be found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotFound(SecretId),

    /// Error generated if we could not find a create vault event
    /// in a collection of event records or as the first event in
    /// a folder event log.
    #[error("could not find create vault event")]
    NoVaultEvent,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the filesystem library.
    #[error(transparent)]
    FileSystem(#[from] sos_filesystem::Error),

    /// Error generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Error generated by the login library.
    #[error(transparent)]
    Login(#[from] sos_login::Error),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Authentication errors.
    #[error(transparent)]
    Authentication(#[from] sos_core::AuthenticationError),

    #[cfg(feature = "search")]
    /// Errors generated by the search library.
    #[error(transparent)]
    Search(#[from] sos_search::Error),

    /// Errors generated by the password library.
    #[error(transparent)]
    Password(#[from] sos_password::Error),

    /// Errors generated by the sync library.
    #[error(transparent)]
    Sync(#[from] sos_sync::Error),

    /// Errors generated by the backend storage.
    #[error(transparent)]
    BackendStorage(#[from] sos_backend::StorageError),

    /// Errors generated by the backend library.
    #[error(transparent)]
    Backend(#[from] sos_backend::Error),

    /// Errors generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the AGE library when encrypting.
    #[cfg(feature = "files")]
    #[error(transparent)]
    AgeEncrypt(#[from] age::EncryptError),

    /// Error generated by the AGE library when decrypting.
    #[cfg(feature = "files")]
    #[error(transparent)]
    AgeDecrypt(#[from] age::DecryptError),
}

impl ErrorExt for Error {
    fn is_secret_not_found(&self) -> bool {
        matches!(self, Error::SecretNotFound(_))
    }

    fn is_forbidden(&self) -> bool {
        matches!(
            self,
            Error::Authentication(AuthenticationError::NotAuthenticated)
        )
    }

    fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            Error::Vault(sos_vault::Error::Authentication(
                AuthenticationError::PasswordVerification
            ))
        )
    }
}
