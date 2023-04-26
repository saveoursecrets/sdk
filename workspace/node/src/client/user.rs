//! Network aware user storage and search index.
use std::{collections::HashSet, path::Path, sync::Arc};

use sos_core::{
    account::{
        AccountBackup, AuthenticatedUser, DelegatedPassphrase, LocalAccounts,
        Login,
    },
    decode, encode,
    search::{Document, DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    vault::{
        secret::{kind::CONTACT, Secret, SecretId, SecretMeta},
        Gatekeeper, Summary, Vault, VaultAccess, VaultFileAccess, VaultId,
    },
    vcard4, Timestamp,
};

use parking_lot::RwLock as SyncRwLock;
use secrecy::{ExposeSecret, SecretString};

use super::{
    provider::{BoxedProvider, ProviderFactory},
    Result,
};

#[cfg(feature = "peer")]
use crate::peer::convert_libp2p_identity;

#[cfg(feature = "device")]
use crate::device::{self, TrustedDevice};

/// Authenticated user with storage provider.
pub struct UserStorage {
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Storage provider.
    pub storage: BoxedProvider,
    /// Factory user to create the storage provider.
    pub factory: ProviderFactory,
    /// Search index.
    pub index: UserIndex,
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
            #[cfg(feature = "peer")]
            peer_key,
        })
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

    /// Load trusted devices.
    #[cfg(feature = "device")]
    pub fn load_devices(&self) -> Result<Vec<TrustedDevice>> {
        use sos_core::storage::StorageDirs;
        let device_dir = StorageDirs::devices_dir(
            self.user.identity().address().to_string(),
        )?;
        let devices = device::TrustedDevice::load_devices(device_dir)?;
        let mut trusted = Vec::new();
        for device in devices {
            trusted.push(device);
        }
        Ok(trusted)
    }

    /// Add a trusted device.
    #[cfg(feature = "device")]
    pub fn add_device(&mut self, device: TrustedDevice) -> Result<()> {
        use sos_core::storage::StorageDirs;
        let device_dir = StorageDirs::devices_dir(
            self.user.identity().address().to_string(),
        )?;
        device::TrustedDevice::add_device(device_dir, device)?;
        Ok(())
    }

    /// Remove a trusted device.
    #[cfg(feature = "device")]
    pub fn remove_device(&mut self, device: TrustedDevice) -> Result<()> {
        use sos_core::storage::StorageDirs;
        let device_dir = StorageDirs::devices_dir(
            self.user.identity().address().to_string(),
        )?;
        device::TrustedDevice::remove_device(device_dir, &device)?;
        Ok(())
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

/// Modify and query a search index.
pub struct UserIndex {
    /// Search index.
    search_index: Arc<SyncRwLock<SearchIndex>>,
}

impl UserIndex {
    /// Create a new user search index.
    pub fn new() -> Self {
        Self {
            search_index: Arc::new(SyncRwLock::new(SearchIndex::new(None))),
        }
    }

    /// Clear the entire search index.
    pub fn clear(&mut self) {
        let mut writer = self.search_index.write();
        writer.remove_all();
    }

    /// Remove a folder from the search index.
    pub fn remove_folder_from_search_index(&self, vault_id: &VaultId) {
        // Clean entries from the search index
        let mut writer = self.search_index.write();
        writer.remove_vault(vault_id);
    }

    /// Add a folder to the search index.
    pub fn add_folder_to_search_index(
        &self,
        vault: Vault,
        passphrase: SecretString,
    ) -> Result<()> {
        let index = Arc::clone(&self.search_index);
        let mut keeper = Gatekeeper::new(vault, Some(index));
        keeper.unlock(passphrase)?;
        keeper.create_search_index()?;
        keeper.lock();
        Ok(())
    }

    /// Get the search index document count statistics.
    pub fn document_count(&self) -> DocumentCount {
        let reader = self.search_index.read();
        reader.statistics().count().clone()
    }

    /// Determine if a document exists in a folder.
    pub fn document_exists_in_folder(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> bool {
        let reader = self.search_index.read();
        reader.find_by_label(vault_id, label, id).is_some()
    }

    /// Query with document views.
    pub fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let index_reader = self.search_index.read();
        let mut docs = Vec::with_capacity(index_reader.len());
        for doc in index_reader.values_iter() {
            for view in &views {
                if view.test(doc, archive.as_ref()) {
                    docs.push(doc.clone());
                }
            }
        }
        Ok(docs)
    }

    /// Query the search index.
    pub fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let index_reader = self.search_index.read();
        let mut docs = Vec::new();
        let tags: HashSet<_> = filter.tags.iter().cloned().collect();
        let predicate = self.query_predicate(filter, tags, None);
        if !query.is_empty() {
            for doc in index_reader.query_map(query, predicate) {
                docs.push(doc.clone());
            }
        } else {
            for doc in index_reader.values_iter() {
                if predicate(doc) {
                    docs.push(doc.clone());
                }
            }
        }
        Ok(docs)
    }

    fn query_predicate(
        &self,
        filter: QueryFilter,
        tags: HashSet<String>,
        _archive: Option<ArchiveFilter>,
    ) -> impl Fn(&Document) -> bool {
        move |doc| {
            let tag_match = filter.tags.is_empty() || {
                !tags
                    .intersection(doc.meta().tags())
                    .collect::<HashSet<_>>()
                    .is_empty()
            };

            let vault_id = doc.vault_id();
            let folder_match = filter.folders.is_empty()
                || filter.folders.contains(vault_id);

            let type_match = filter.types.is_empty()
                || filter.types.contains(doc.meta().kind());

            tag_match && folder_match && type_match
        }
    }
}

/// View of documents in the search index.
pub enum DocumentView {
    /// View all documents in the search index.
    All {
        /// List of secret types to ignore.
        ignored_types: Option<Vec<u8>>,
    },
    /// View all the documents for a folder.
    Vault(VaultId),
    /// View documents across all vaults by type identifier.
    TypeId(u8),
    /// View for all favorites.
    Favorites,
    /// View documents that have one or more tags.
    Tags(Vec<String>),
    /// Contacts of the given types.
    Contact {
        /// Contact types to include in the results.
        include_types: Option<Vec<vcard4::property::Kind>>,
    },
    /// Documents with the specific identifiers.
    Documents {
        /// Vault identifier.
        vault_id: VaultId,
        /// Secret identifiers.
        identifiers: Vec<SecretId>,
    },
}

impl DocumentView {
    /// Test this view against a search result document.
    pub fn test(
        &self,
        doc: &Document,
        archive: Option<&ArchiveFilter>,
    ) -> bool {
        if let Some(filter) = archive {
            if !filter.include_documents && doc.vault_id() == &filter.id {
                return false;
            }
        }

        match self {
            DocumentView::All { ignored_types } => {
                if let Some(ignored_types) = ignored_types {
                    return !ignored_types.contains(doc.meta().kind());
                }
                true
            }
            DocumentView::Vault(vault_id) => doc.vault_id() == vault_id,
            DocumentView::TypeId(type_id) => doc.meta().kind() == type_id,
            DocumentView::Favorites => doc.meta().favorite(),
            DocumentView::Tags(tags) => {
                let tags: HashSet<_> = tags.iter().cloned().collect();
                !tags
                    .intersection(doc.meta().tags())
                    .collect::<HashSet<_>>()
                    .is_empty()
            }
            DocumentView::Contact { include_types } => {
                if doc.meta().kind() == &CONTACT {
                    if let Some(include_types) = include_types {
                        if let Some(contact_type) = &doc.extra().contact_type
                        {
                            let contact_type: vcard4::property::Kind =
                                contact_type.clone();
                            return include_types.contains(&contact_type);
                        } else {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }
            DocumentView::Documents {
                vault_id,
                identifiers,
            } => doc.vault_id() == vault_id && identifiers.contains(doc.id()),
        }
    }
}

/// Filter for a search query.
pub struct QueryFilter {
    /// List of tags.
    pub tags: Vec<String>,
    /// List of vault identifiers.
    pub folders: Vec<VaultId>,
    /// List of type identifiers.
    pub types: Vec<u8>,
}

/// Filter for archived documents.
pub struct ArchiveFilter {
    /// Identifier of the archive vault.
    pub id: VaultId,
    /// Whether to include archived documents.
    pub include_documents: bool,
}
