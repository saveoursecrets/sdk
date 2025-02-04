//! Create and manage local accounts for the
//! [Save Our Secrets](https://saveoursecrets.com) SDK.
mod account_switcher;
mod builder;
mod convert;
mod error;
mod local_account;
mod sync;
mod traits;
mod types;

pub use account_switcher::{
    AccountSwitcher, AccountSwitcherOptions, LocalAccountSwitcher,
};
pub use builder::{AccountBuilder, PrivateNewAccount};
pub use convert::CipherComparison;
pub use error::Error;
pub use local_account::LocalAccount;
pub use traits::Account;
pub use types::{
    AccountChange, AccountData, DetachedView, FolderChange, FolderCreate,
    FolderDelete, SecretChange, SecretDelete, SecretInsert, SecretMove,
};

#[cfg(feature = "contacts")]
pub use types::ContactImportProgress;

#[cfg(feature = "clipboard")]
pub use {
    types::{ClipboardCopyRequest, ClipboardTextFormat},
    xclipboard,
};

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
