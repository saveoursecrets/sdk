use sos_core::{
    account::{AuthenticatedUser, DelegatedPassphrase},
    vault::{Summary, VaultAccess, VaultFileAccess},
};

use super::{
    provider::{BoxedProvider, ProviderFactory},
    Result,
};

/// Authenticated user with storage provider.
pub struct UserStorage {
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Storage provider.
    pub storage: BoxedProvider,
    /// Key pair for peer to peer connections.
    #[cfg(feature = "peer")]
    pub peer_key: libp2p::identity::Keypair,
    /// Factory user to create the storage provider.
    pub factory: ProviderFactory,
}

impl UserStorage {
    /// Create a folder (vault).
    pub async fn create_folder(&mut self, name: String) -> Result<Summary> {
        let passphrase = DelegatedPassphrase::generate_vault_passphrase()?;

        let (_, summary) = self
            .storage
            .create_vault(name, Some(passphrase.clone()))
            .await?;

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity_mut().keeper_mut(),
            summary.id(),
            passphrase,
        )?;

        Ok(summary)
    }

    /// Delete a folder (vault).
    pub async fn remove_folder(&mut self, summary: &Summary) -> Result<()> {
        self.storage.remove_vault(summary).await?;
        DelegatedPassphrase::remove_vault_passphrase(
            self.user.identity_mut().keeper_mut(),
            summary.id(),
        )?;

        /*
        // Clean entries from the search index
        let mut index = SEARCH_INDEX.write();
        let mut index_writer =
            index.as_mut().ok_or(Error::NoSearchIndex)?.write();
        index_writer.remove_vault(summary.id());
        */

        Ok(())
    }

    /// Rename a folder (vault).
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<()> {
        // Update the provider
        self.storage.set_vault_name(summary, &name).await?;

        // Now update the in-memory name for the current selected vault
        if let Some(keeper) = self.storage.current_mut() {
            if keeper.vault().id() == summary.id() {
                keeper.set_vault_name(name.clone())?;
            }
        }

        // Update the vault on disc
        let vault_path = self.storage.vault_path(summary);
        let mut access = VaultFileAccess::new(vault_path)?;
        access.set_vault_name(name)?;

        Ok(())
    }
}
