//! Create and manage local accounts.
mod account;
#[cfg(feature = "archive")]
pub mod archive;
mod builder;
mod convert;
#[cfg(feature = "preferences")]
pub mod preferences;
#[cfg(feature = "security-report")]
pub mod security_report;
#[cfg(feature = "sync")]
mod sync;
#[cfg(feature = "system-messages")]
pub mod system_messages;

pub use account::{
    Account, AccountChange, AccountData, DetachedView, FolderChange,
    FolderCreate, FolderDelete, LocalAccount, SecretChange, SecretDelete,
    SecretInsert, SecretMove,
};
pub use builder::{AccountBuilder, PrivateNewAccount};
pub use convert::CipherComparison;

#[cfg(feature = "contacts")]
pub use account::ContactImportProgress;
