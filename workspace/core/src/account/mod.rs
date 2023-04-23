//! Create and manage local accounts.
//mod backup;
mod builder;
#[cfg(not(target_arch = "wasm32"))]
mod local;
mod passphrase;

//pub use backup::AccountBackup;
pub use builder::{AccountBuilder, ImportedAccount, NewAccount};
#[cfg(not(target_arch = "wasm32"))]
pub use local::{AccountInfo, LocalAccounts};
pub use passphrase::DelegatedPassphrase;
