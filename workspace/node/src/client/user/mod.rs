//! Network aware user storage and search index.
use std::{path::Path, sync::Arc};

use sos_core::{
    account::{
        AccountBackup, AuthenticatedUser, DelegatedPassphrase, LocalAccounts,
        Login,
    },
    decode, encode,
    events::SyncEvent,
    search::{DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Gatekeeper, Summary, Vault, VaultAccess, VaultFileAccess, VaultId,
    },
    Timestamp,
};

use parking_lot::RwLock as SyncRwLock;
use secrecy::{ExposeSecret, SecretString};

use crate::client::{
    provider::{BoxedProvider, ProviderFactory},
    Error, Result,
};

#[cfg(feature = "peer")]
use crate::peer::convert_libp2p_identity;

#[cfg(feature = "device")]
mod devices;
mod search_index;

#[cfg(feature = "device")]
pub use devices::DeviceManager;

pub use search_index::*;

/// Authenticated user with storage provider.
pub struct UserStorage {
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Storage provider.
    pub storage: BoxedProvider,
    /// Factory user to create the storage provider.
    pub factory: ProviderFactory,
    /// Search index.
    index: UserIndex,
    /// Devices for this user.
    #[cfg(feature = "device")]
    devices: DeviceManager,
    /// Key pair for peer to peer connections.
    #[cfg(feature = "peer")]
    pub peer_key: libp2p::identity::Keypair,
}

impl UserStorage {
    /// Create new user storage by signing in to an account.
    pub async fn new(
        address: &Address,
        passphrase: SecretString,
        factory: ProviderFactory,
    ) -> Result<Self> {
        let identity_index =
            Arc::new(SyncRwLock::new(SearchIndex::new(None)));
        let user = Login::sign_in(address, passphrase, identity_index)?;

        // Signing key for the storage provider
        let signer = user.identity().signer().clone();
        let (mut storage, _) = factory.create_provider(signer)?;
        storage.authenticate().await?;

        #[cfg(feature = "peer")]
        let peer_key = convert_libp2p_identity(user.device().signer())?;

        Ok(Self {
            user,
            storage,
            factory,
            index: UserIndex::new(),
            #[cfg(feature = "device")]
            devices: DeviceManager::new(address)?,
            #[cfg(feature = "peer")]
            peer_key,
        })
    }

    /// Users devices reference.
    #[cfg(feature = "device")]
    pub fn devices(&self) -> &DeviceManager {
        &self.devices
    }

    /// Users devices mutable reference.
    #[cfg(feature = "device")]
    pub fn devices_mut(&mut self) -> &mut DeviceManager {
        &mut self.devices
    }

    /// List folders.
    pub async fn list_folders(&mut self) -> Result<Vec<Summary>> {
        let summaries = self.storage.load_vaults().await?;
        Ok(summaries.to_vec())
    }

    /// Sign out of the account.
    pub fn sign_out(&mut self) {
        self.index.clear();
        self.storage.close_vault();
        self.user.sign_out();
    }

    /// Create a folder.
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

    /// Delete a folder.
    pub async fn remove_folder(&mut self, summary: &Summary) -> Result<()> {
        self.storage.remove_vault(summary).await?;
        DelegatedPassphrase::remove_vault_passphrase(
            self.user.identity_mut().keeper_mut(),
            summary.id(),
        )?;
        self.index.remove_folder_from_search_index(summary.id());
        Ok(())
    }

    /// Rename a folder.
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
    ) -> Result<Summary> {
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

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            if let Some(current) = self.storage.current() {
                if current.id() == summary.id() {
                    self.storage.close_vault();
                }
            }

            // Clean entries from the search index
            self.index.remove_folder_from_search_index(summary.id());
        }

        // Ensure the imported secrets are in the search index
        self.index.add_folder_to_search_index(vault, passphrase)?;

        Ok(summary)
    }

    /// Open a vault.
    pub fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        let passphrase = DelegatedPassphrase::find_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
        )?;

        // If the target vault is already open then this is a noop
        // as opening a vault is an expensive operation
        if let Some(current) = self.storage.current().as_ref() {
            if current.id() == summary.id() {
                return Ok(());
            }
        }

        let index = Arc::clone(&self.index.search_index);
        self.storage.open_vault(summary, passphrase, Some(index))?;
        Ok(())
    }

    /// Create a secret in the current open folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<(SecretId, SyncEvent<'static>)> {
        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event =
            self.storage.create_secret(meta, secret).await?.into_owned();

        let id = if let SyncEvent::CreateSecret(id, _) = &event {
            *id
        } else {
            unreachable!();
        };

        Ok((id, event))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<(SecretData, SyncEvent<'static>)> {
        let (meta, secret, event) =
            self.storage.read_secret(secret_id).await?;
        Ok((
            SecretData {
                id: Some(*secret_id),
                meta,
                secret,
            },
            event.into_owned(),
        ))
    }

    /// Update a secret in the current open folder.
    pub async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        mut destination: Option<&Summary>,
    ) -> Result<(SecretId, SyncEvent<'static>)> {
        let secret = if let Some(secret) = secret {
            secret
        } else {
            let (data, _) = self.read_secret(secret_id).await?;
            data.secret
        };

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let current_folder =
            self.storage.current().map(|g| g.vault().summary().clone());

        let event =
            self.storage.update_secret(secret_id, meta, secret).await?;

        if let (Some(summary), Some(destination)) =
            (current_folder, destination.take())
        {
            let (new_id, _, create_event, _) =
                self.move_secret(&summary, destination, secret_id).await?;
            return Ok((new_id, create_event));
        }

        Ok((*secret_id, event.into_owned()))
    }

    /// Move a secret between folders.
    ///
    /// The from folder must already be open.
    pub async fn move_secret(
        &mut self,
        from: &Summary,
        to: &Summary,
        secret_id: &SecretId,
    ) -> Result<(
        SecretId,
        SyncEvent<'static>,
        SyncEvent<'static>,
        SyncEvent<'static>,
    )> {
        let (data, read_event) = self.read_secret(secret_id).await?;
        self.open_folder(to)?;
        let (new_id, create_event) =
            self.create_secret(data.meta, data.secret).await?;
        self.open_folder(from)?;
        let delete_event = self.delete_secret(secret_id).await?;
        Ok((
            new_id,
            read_event.into_owned(),
            create_event.into_owned(),
            delete_event.into_owned(),
        ))
    }

    /// Delete a secret.
    pub async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<SyncEvent<'_>> {
        Ok(self.storage.delete_secret(secret_id).await?)
    }

    /// Search index reference.
    pub fn index(&self) -> &UserIndex {
        &self.index
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> &mut UserIndex {
        &mut self.index
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        // Find the id of an archive folder
        let summaries = {
            let summaries = self.list_folders().await?;
            let mut archive: Option<VaultId> = None;
            for summary in &summaries {
                if summary.flags().is_archive() {
                    archive = Some(*summary.id());
                    break;
                }
            }
            let mut writer = self.index.search_index.write();
            writer.set_archive_id(archive);
            summaries
        };
        Ok((self.build_search_index().await?, summaries))
    }

    /// Build the search index for all folders.
    pub async fn build_search_index(&mut self) -> Result<DocumentCount> {
        // Clear search index first
        self.index.clear();

        // Build search index from all the vaults
        let summaries = self.list_folders().await?;
        for summary in summaries {
            // Must open the vault so the provider state unlocks
            // the vault
            self.open_folder(&summary)?;

            // Add the vault meta data to the search index
            self.storage.create_search_index()?;
            // Close the vault as we are done for now
            self.storage.close_vault();
        }

        Ok(self.index.document_count())
    }
}
