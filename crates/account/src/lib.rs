//! Create and manage local accounts for the [Save Our Secrets](https://saveoursecrets.com) SDK.
mod account;
mod account_switcher;
#[cfg(feature = "archive")]
pub use sos_backup_archive as archive;
mod builder;
mod convert;
mod error;

mod folder_sync;
mod sync;

pub use account::{
    Account, AccountChange, AccountData, DetachedView, FolderChange,
    FolderCreate, FolderDelete, LocalAccount, SecretChange, SecretDelete,
    SecretInsert, SecretMove,
};
pub use account_switcher::{
    AccountSwitcher, AccountSwitcherOptions, LocalAccountSwitcher,
};
pub use builder::{AccountBuilder, PrivateNewAccount};
pub use convert::CipherComparison;
pub use error::Error;

#[cfg(feature = "contacts")]
pub use account::ContactImportProgress;

#[cfg(feature = "clipboard")]
pub use {account::ClipboardCopyRequest, xclipboard};

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
