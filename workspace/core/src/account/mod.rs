//! Create and manage local accounts.
#[cfg(not(target_arch = "wasm32"))]
mod backup;
mod builder;
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
#[cfg(not(target_arch = "wasm32"))]
pub use local::{AccountInfo, LocalAccounts};
#[cfg(not(target_arch = "wasm32"))]
pub use login::{DeviceSigner, Login};
pub use passphrase::DelegatedPassphrase;
