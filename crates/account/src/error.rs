//! Errors generated by the account library.
use sos_sdk::prelude::VaultId;
use thiserror::Error;
use uuid::Uuid;

/// Error generated by the account library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a folder password could not be located.
    #[error("could not find folder password for '{0}'")]
    NoFolderPassword(VaultId),

    /// Error generated accessing an account that is not
    /// authenticated.
    #[error("account not authenticated, sign in required")]
    NotAuthenticated,

    /// Error generated when no storage is configured.
    #[error(
        "account is empty, you may need to initialize the account or sign in"
    )]
    NoStorage,

    /// Error generated when no default folder is available.
    #[error("no default folder")]
    NoDefaultFolder,

    /// Error generated when an open folder is expected.
    #[error("no open folder")]
    NoOpenFolder,

    /// Error generated when a PEM-encoded certificate is invalid.
    #[error("invalid PEM encoding")]
    PemEncoding,

    /// Error generated when an archive folder is not available.
    #[error("archive folder does not exist")]
    NoArchive,

    /// Error generated when attempting to unarchive a secret that
    /// is not archived.
    #[error("cannot unarchive, not archived")]
    NotArchived,

    /// Error generated attempting to access a vault that is not available.
    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),

    /// Error generated when attempting to archive a secret that
    /// is already archived.
    #[error("cannot move to archive, already archived")]
    AlreadyArchived,

    /// Error generated when a contacts folder is not available.
    #[cfg(feature = "contacts")]
    #[error("no contacts folder")]
    NoContactsFolder,

    /// Error generated when a secret is not a contact secret.
    #[cfg(feature = "contacts")]
    #[error("not a contact")]
    NotContact,

    /// Error generated when an archive is for an address that does
    /// not exist locally when we are expecting an archive to be imported
    /// in the context of an existing account.
    #[error("could not find account for archive address {0}")]
    NoArchiveAccount(String),

    /// Error generated attempting to restore an account from an archive
    /// whilst not authenticated and the address for the archive matches
    /// an account that already exists.
    #[error("account for archive address {0} already exists")]
    ArchiveAccountAlreadyExists(String),

    /// Error generated by the JSON path library when no nodes matched.
    #[cfg(feature = "clipboard")]
    #[error("paths '{0:?}' did not match any nodes")]
    JsonPathQueryEmpty(Vec<String>),

    #[cfg(feature = "clipboard")]
    /// Error when no clipboard is configured.
    #[error("clipboard is not configured")]
    NoClipboard,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Error generated by the database library.
    #[error(transparent)]
    Database(#[from] sos_database::Error),

    /// Error generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the VCard library.
    #[cfg(feature = "contacts")]
    #[error(transparent)]
    Vcard(#[from] vcard4::Error),

    /// Error generated by the clipboard library.
    #[cfg(feature = "clipboard")]
    #[error(transparent)]
    Clipboard(#[from] xclipboard::Error),

    /// Error generated attempting to detect the system time zone.
    #[cfg(feature = "clipboard")]
    #[error(transparent)]
    TimeZone(#[from] time_tz::system::Error),
}
