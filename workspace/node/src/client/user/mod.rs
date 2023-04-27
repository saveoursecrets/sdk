//! Network aware user storage and search index.
use std::{
    io::{Read, Seek},
    path::{Path, PathBuf},
    sync::Arc,
};

use sos_core::{
    account::{
        archive::Inventory, AccountBackup, AccountInfo, AuthenticatedUser,
        DelegatedPassphrase, ExtractFilesLocation, LocalAccounts, Login,
        RestoreOptions,
    },
    decode, encode,
    events::SyncEvent,
    search::{DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    storage::{EncryptedFile, FileStorage, StorageDirs},
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

#[cfg(feature = "migrate")]
pub use sos_migrate::{
    import::{ImportFormat, ImportTarget},
    Convert,
};

pub use search_index::*;

#[cfg(feature = "contacts")]
/// Progress event when importing contacts.
pub enum ContactImportProgress {
    /// Progress event when the number of contacts is known.
    Ready {
        /// Total number of contacts.
        total: usize,
    },
    /// Progress event when a contact is being imported.
    Item {
        /// Label of the contact.
        label: String,
        /// Index of the contact.
        index: usize,
    },
}

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

    /// Files directory.
    files_dir: PathBuf,

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

        let files_dir =
            StorageDirs::files_dir(user.identity().address().to_string())?;

        Ok(Self {
            user,
            storage,
            factory,
            files_dir,
            index: UserIndex::new(),
            #[cfg(feature = "device")]
            devices: DeviceManager::new(address)?,
            #[cfg(feature = "peer")]
            peer_key,
        })
    }

    /// Delete the account for this user and sign out.
    pub fn delete_account(&mut self) -> Result<()> {
        self.user.delete_account()?;
        self.sign_out();
        Ok(())
    }

    /// Rename this account.
    pub fn rename_account(&mut self, account_name: String) -> Result<()> {
        Ok(self.user.rename_account(account_name)?)
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

    /// Get the expected location for a file.
    pub fn file_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<PathBuf> {
        Ok(StorageDirs::file_location(
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
            file_name,
        )?)
    }

    /// Encrypt a file and move it to the external file storage location.
    pub fn encrypt_file_storage<P: AsRef<Path>>(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        source: P,
    ) -> Result<EncryptedFile> {
        // Find the file encryption password
        let password = DelegatedPassphrase::find_file_encryption_passphrase(
            self.user.identity().keeper(),
        )?;

        // Encrypt and write to disc
        Ok(FileStorage::encrypt_file_storage(
            password,
            source,
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
        )?)
    }

    /// Decrypt a file in the storage location and return the buffer.
    pub fn decrypt_file_storage(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        // Find the file encryption password
        let password = DelegatedPassphrase::find_file_encryption_passphrase(
            self.user.identity().keeper(),
        )?;

        Ok(FileStorage::decrypt_file_storage(
            &password,
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
            file_name,
        )?)
    }

    /// Delete a file from the storage location.
    pub fn delete_file_storage(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<()> {
        let vault_path = self.files_dir.join(vault_id.to_string());
        let secret_path = vault_path.join(secret_id.to_string());
        let path = secret_path.join(file_name);

        std::fs::remove_file(path)?;

        // Prune empty directories
        let secret_dir_is_empty = secret_path.read_dir()?.next().is_none();
        if secret_dir_is_empty {
            std::fs::remove_dir(secret_path)?;
        }
        let vault_dir_is_empty = vault_path.read_dir()?.next().is_none();
        if vault_dir_is_empty {
            std::fs::remove_dir(vault_path)?;
        }

        Ok(())
    }

    /// Move the encrypted file for an external storage.
    pub fn move_file_storage(
        &self,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        file_name: &str,
    ) -> Result<()> {
        let old_vault_path = self.files_dir.join(old_vault_id.to_string());
        let old_secret_path = old_vault_path.join(old_secret_id.to_string());
        let old_path = old_secret_path.join(file_name);

        let new_path = self
            .files_dir
            .join(new_vault_id.to_string())
            .join(new_secret_id.to_string())
            .join(file_name);

        if let Some(parent) = new_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::rename(old_path, new_path)?;

        // Prune empty directories
        let secret_dir_is_empty =
            old_secret_path.read_dir()?.next().is_none();
        if secret_dir_is_empty {
            std::fs::remove_dir(old_secret_path)?;
        }
        let vault_dir_is_empty = old_vault_path.read_dir()?.next().is_none();
        if vault_dir_is_empty {
            std::fs::remove_dir(old_vault_path)?;
        }

        Ok(())
    }

    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    #[cfg(feature = "migrate")]
    pub fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        use sos_migrate::export::PublicExport;
        use std::collections::HashMap;
        use std::io::Cursor;

        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = LocalAccounts::list_local_vaults(
            self.user.identity().address(),
            false,
        )?;

        for (summary, _) in vaults {
            let (vault, _) = LocalAccounts::find_local_vault(
                self.user.identity().address(),
                summary.id(),
                false,
            )?;
            let vault_passphrase =
                DelegatedPassphrase::find_vault_passphrase(
                    self.user.identity().keeper(),
                    summary.id(),
                )?;

            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(vault_passphrase)?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper)?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer = serde_json::to_vec_pretty(self.user.account())?;
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files)?;
        migration.finish()?;

        std::fs::write(path.as_ref(), &archive)?;

        Ok(())
    }

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        use sos_migrate::import::csv::{
            bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
            dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
            macos::MacPasswordCsv, one_password::OnePasswordCsv,
        };

        match target.format {
            ImportFormat::OnePasswordCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    OnePasswordCsv,
                )
                .await
            }
            ImportFormat::DashlaneZip => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    DashlaneCsvZip,
                )
                .await
            }
            ImportFormat::BitwardenCsv => {
                self.import_csv(target.path, target.folder_name, BitwardenCsv)
                    .await
            }
            ImportFormat::ChromeCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    ChromePasswordCsv,
                )
                .await
            }
            ImportFormat::FirefoxCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    FirefoxPasswordCsv,
                )
                .await
            }
            ImportFormat::MacosCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    MacPasswordCsv,
                )
                .await
            }
        }
    }

    /// Generic CSV import implementation.
    #[cfg(feature = "migrate")]
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<Summary> {
        let vaults = LocalAccounts::list_local_vaults(
            self.user.identity().address(),
            false,
        )?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == &folder_name);

        let vault_passphrase =
            DelegatedPassphrase::generate_vault_passphrase()?;

        let mut vault: Vault = Default::default();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault.id())
        } else {
            folder_name
        };
        vault.set_name(name);
        vault.initialize(vault_passphrase.clone(), None)?;

        // Parse the CSV records into the vault
        let vault = converter.convert(
            path.as_ref().to_path_buf(),
            vault,
            vault_passphrase.clone(),
        )?;

        let buffer = encode(&vault)?;
        self.storage.import_vault(buffer).await?;

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity_mut().keeper_mut(),
            vault.id(),
            vault_passphrase.clone(),
        )?;

        let summary = vault.summary().clone();

        // Ensure the imported secrets are in the search index
        self.index_mut()
            .add_folder_to_search_index(vault, vault_passphrase)?;

        Ok(summary)
    }

    /// Get an avatar JPEG image for a contact in the current
    /// open folder.
    #[cfg(feature = "contacts")]
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<Option<Vec<u8>>> {
        let (data, _) = self.read_secret(secret_id).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let jpeg = if let Ok(mut jpegs) = vcard.parse_photo_jpeg() {
                if !jpegs.is_empty() {
                    Some(jpegs.remove(0))
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(jpeg);
        }
        Ok(None)
    }

    /// Export a contact secret to vCard file.
    ///
    /// The folder containing the secret should already be open.
    #[cfg(feature = "contacts")]
    pub async fn export_vcard_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        secret_id: &SecretId,
    ) -> Result<()> {
        let (data, _) = self.read_secret(secret_id).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let content = vcard.to_string();
            std::fs::write(&path, content)?;
        } else {
            return Err(Error::NotContact);
        }
        Ok(())
    }

    /// Export all contacts to a single vCard.
    #[cfg(feature = "contacts")]
    pub async fn export_all_vcards<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        let summaries = self.list_folders().await?;
        let contacts = summaries.iter().find(|s| s.flags().is_contact());
        let contacts = contacts.ok_or_else(|| Error::NoContactsFolder)?;

        let contacts_passphrase = DelegatedPassphrase::find_vault_passphrase(
            self.user.identity().keeper(),
            contacts.id(),
        )?;
        let (vault, _) = LocalAccounts::find_local_vault(
            self.user.identity().address(),
            contacts.id(),
            false,
        )?;
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(contacts_passphrase)?;

        let mut vcf = String::new();
        let keys: Vec<&SecretId> = keeper.vault().keys().collect();
        for key in keys {
            if let Some((_, secret, _)) = keeper.read(key)? {
                if let Secret::Contact { vcard, .. } = secret {
                    vcf.push_str(&vcard.to_string());
                }
            }
        }
        std::fs::write(path, vcf.as_bytes())?;
        Ok(())
    }

    /// Import vCards from a string buffer.
    ///
    /// The contacts folder should already be the current open folder.
    #[cfg(feature = "contacts")]
    pub async fn import_vcard(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) -> (),
    ) -> Result<()> {
        use sos_core::vcard4::parse;
        let cards = parse(content)?;

        progress(ContactImportProgress::Ready { total: cards.len() });

        for (index, vcard) in cards.into_iter().enumerate() {
            let label = vcard
                .formatted_name
                .get(0)
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let secret = Secret::Contact {
                vcard: Box::new(vcard),
                user_data: Default::default(),
            };

            progress(ContactImportProgress::Item {
                label: label.clone(),
                index,
            });

            let meta = SecretMeta::new(label, secret.kind());
            self.storage.create_secret(meta, secret).await?;
        }

        Ok(())
    }

    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub fn export_archive_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        Ok(AccountBackup::export_archive_file(
            path,
            self.user.identity().address(),
        )?)
    }

    /// Read the inventory from an archive.
    pub fn restore_archive_inventory<R: Read + Seek>(
        buffer: R,
    ) -> Result<Inventory> {
        let mut inventory = AccountBackup::restore_archive_inventory(buffer)?;
        let accounts = LocalAccounts::list_accounts()?;
        let exists_local = accounts
            .iter()
            .any(|account| account.address() == &inventory.manifest.address);
        inventory.exists_local = exists_local;
        Ok(inventory)
    }

    /// Import from an archive file.
    pub async fn restore_archive_file<P: AsRef<Path>>(
        owner: Option<&mut UserStorage>,
        path: P,
        options: RestoreOptions,
    ) -> Result<AccountInfo> {
        let file = std::fs::File::open(path)?;
        Self::restore_archive_reader(owner, file, options).await
    }

    /// Import from an archive buffer.
    pub async fn restore_archive_reader<R: Read + Seek>(
        mut owner: Option<&mut UserStorage>,
        buffer: R,
        mut options: RestoreOptions,
    ) -> Result<AccountInfo> {
        let files_dir = if let Some(owner) = owner.as_ref() {
            ExtractFilesLocation::Path(StorageDirs::files_dir(
                owner.user.identity().address().to_string(),
            )?)
        } else {
            ExtractFilesLocation::Builder(Box::new(|address| {
                StorageDirs::files_dir(address).ok()
            }))
        };

        options.files_dir = Some(files_dir);

        let (targets, account) = AccountBackup::restore_archive_buffer(
            buffer,
            options,
            owner.is_some(),
        )?;

        if let Some(owner) = owner.as_mut() {
            owner.storage.restore_archive(&targets).await?;
            owner.build_search_index().await?;
        }

        Ok(account)
    }
}
