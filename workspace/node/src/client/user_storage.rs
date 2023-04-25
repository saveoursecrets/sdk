use std::path::Path;

use sos_core::{
    account::{
        AccountBackup, AuthenticatedUser, DelegatedPassphrase, LocalAccounts,
    },
    decode, encode,
    vault::{
        secret::{Secret, SecretMeta},
        Gatekeeper, Summary, Vault, VaultAccess, VaultFileAccess,
    },
    Timestamp,
};

use secrecy::{ExposeSecret, SecretString};

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

    /// Export a folder (vault).
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_passphrase: SecretString,
        save_passphrase: bool,
    ) -> Result<()> {
        let buffer = AccountBackup::export_vault(
            self.user.identity().address(),
            self.user.identity().keeper(),
            summary.id(),
            new_passphrase.clone(),
        )?;

        let address = self.user.identity().address().to_owned();

        if save_passphrase {
            let (default_summary, _) =
                LocalAccounts::find_default_vault(&address)?;

            let passphrase = DelegatedPassphrase::find_vault_passphrase(
                self.user.identity().keeper(),
                default_summary.id(),
            )?;

            let timestamp: Timestamp = Default::default();
            let label = format!(
                "Exported folder {}.vault ({})",
                summary.id(),
                timestamp.to_rfc3339()?
            );
            let secret = Secret::Account {
                account: format!("{}.vault", summary.id()),
                url: None,
                password: new_passphrase,
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());

            let (vault, _) = LocalAccounts::find_local_vault(
                self.user.identity().address(),
                default_summary.id(),
                false,
            )?;

            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(passphrase)?;
            keeper.create(meta, secret)?;

            // FIXME: ensure this create event is sent to the
            // FIXME: storage log
        }

        std::fs::write(path, buffer)?;

        Ok(())
    }

    /// Import a folder (vault).
    pub async fn import_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        passphrase: SecretString,
        overwrite: bool,
    ) -> Result<(Summary, Vault)> {
        let buffer = std::fs::read(path.as_ref())?;

        let mut vault: Vault = decode(&buffer)?;

        // Need to verify the passphrase
        vault.verify(passphrase.expose_secret())?;

        // Check for existing identifier
        let vaults = LocalAccounts::list_local_vaults(
            self.user.identity().address(),
            false,
        )?;
        let existing_id =
            vaults.iter().find(|(s, _)| s.id() == vault.summary().id());

        let default_vault =
            vaults.iter().find(|(s, _)| s.flags().is_default());

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            vault.rotate_identifier();
            true
        } else {
            false
        };

        let existing_name = vaults
            .iter()
            .find(|(s, _)| s.name() == vault.summary().name());

        let has_name_changed = if existing_name.is_some() && !overwrite {
            let name = format!(
                "{} ({})",
                vault.summary().name(),
                vault.summary().id()
            );
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
            vault.set_default_flag(false);
        }

        let buffer =
            if has_id_changed || has_name_changed || remove_default_flag {
                // Need to update the buffer as we changed the data
                encode(&vault)?
            } else {
                buffer
            };

        let summary = vault.summary().clone();

        // Import the vault
        self.storage.import_vault(buffer).await?;

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            DelegatedPassphrase::remove_vault_passphrase(
                self.user.identity_mut().keeper_mut(),
                summary.id(),
            )?;
        }

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity_mut().keeper_mut(),
            summary.id(),
            passphrase.clone(),
        )?;

        Ok((summary, vault))
    }
}
