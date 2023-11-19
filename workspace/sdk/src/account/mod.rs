//! Create and manage local accounts.
pub mod archive;
mod backup;
mod builder;
mod identity;
mod local;
mod login;
mod passphrase;
mod paths;

pub use backup::{
    AccountBackup, AccountManifest, ExtractFilesLocation, ManifestEntry,
    RestoreOptions, RestoreTargets,
};
pub use builder::{AccountBuilder, ImportedAccount, NewAccount};
pub use identity::{AccountStatus, Identity, UserIdentity};
pub use local::{AccountInfo, AccountRef, LocalAccounts};
pub use login::{AuthenticatedUser, DeviceSigner, Login};
pub use passphrase::DelegatedPassphrase;
pub use paths::UserPaths;
