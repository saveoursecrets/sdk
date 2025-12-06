//! Trait for delegated password access.
use async_trait::async_trait;
use secrecy::SecretString;
use sos_core::{VaultId, crypto::AccessKey};
use sos_password::diceware::generate_passphrase_words;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Delegated access to folder keys.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DelegatedAccess {
    /// Error type.
    type Error: std::error::Error
        + From<crate::Error>
        + From<sos_password::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static;

    /// Find a folder password.
    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>, Self::Error>;

    /// Remove a folder password.
    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<(), Self::Error>;

    /// Generate a folder password.
    fn generate_folder_password(&self) -> Result<SecretString, Self::Error> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password.
    ///
    /// If a password already exists it is overwritten.
    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<(), Self::Error>;
}
