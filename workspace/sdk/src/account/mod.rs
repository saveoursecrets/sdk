//! Create and manage local accounts.
mod account;
pub mod archive;
mod builder;
#[cfg(feature = "contacts")]
pub mod contacts;
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

pub use account::{
    AccessOptions, Account, AccountData, AccountHandler, DetachedView,
};
pub use builder::{AccountBuilder, NewAccount};
pub use identity::{AccountStatus, Identity};
pub use local::{AccountInfo, AccountRef, AccountsList};
pub use login::{AuthenticatedUser, DeviceSigner};
pub use passphrase::DelegatedPassphrase;
pub use paths::UserPaths;
pub use provider::{FolderStorage, LocalState};

use crate::Result;
use std::path::Path;
