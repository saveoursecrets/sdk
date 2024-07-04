//! Create and manage local accounts.
mod account;
#[cfg(feature = "archive")]
pub mod archive;
mod builder;
mod convert;

pub use account::{
    Account, AccountChange, AccountData, AccountLocked, DetachedView,
    FolderChange, FolderCreate, FolderDelete, LocalAccount, SecretChange,
    SecretDelete, SecretInsert, SecretMove, SigninOptions,
};
pub use builder::{AccountBuilder, PrivateNewAccount};
pub use convert::CipherComparison;

#[cfg(feature = "contacts")]
pub use account::ContactImportProgress;
