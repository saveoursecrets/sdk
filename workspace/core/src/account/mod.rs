//! Create and manage local accounts.
pub mod archive;
#[cfg(not(target_arch = "wasm32"))]
mod backup;
mod builder;
mod identity;
#[cfg(not(target_arch = "wasm32"))]
mod local;
#[cfg(not(target_arch = "wasm32"))]
mod login;
mod passphrase;

#[cfg(not(target_arch = "wasm32"))]
pub use backup::{
    AccountBackup, AccountManifest, ManifestEntry, RestoreOptions,
    RestoreTargets,
};
pub use builder::{AccountBuilder, ImportedAccount, NewAccount};
pub use identity::{Identity, AuthenticatedUser};
#[cfg(not(target_arch = "wasm32"))]
pub use local::{AccountInfo, LocalAccounts};
#[cfg(not(target_arch = "wasm32"))]
pub use login::{DeviceSigner, Login};
pub use passphrase::DelegatedPassphrase;
