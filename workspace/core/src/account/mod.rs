//! Create and manage local accounts.
mod builder;
mod passphrase;

pub use builder::{AccountBuilder, ImportedAccount, NewAccount};
pub use passphrase::{
    generate_vault_passphrase, remove_vault_passphrase, save_vault_passphrase,
};
