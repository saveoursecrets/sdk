//! Storage provider backed by the local filesystem.
use crate::{
    account::{
        search::{AccountSearch, DocumentCount, SearchIndex},
        AccountStatus, FolderKeys, NewAccount, UserPaths,
    },
    commit::{CommitHash, CommitTree},
    constants::VAULT_EXT,
    crypto::{AccessKey, KeyDerivation, PrivateKey},
    decode, encode,
    events::{
        AuditEvent, Event, EventKind, EventReducer, FolderEventLog,
        ReadEvent, WriteEvent,
    },
    passwd::{diceware::generate_passphrase, ChangePassword},
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        FolderRef, Gatekeeper, Header, Summary, Vault, VaultAccess,
        VaultBuilder, VaultCommit, VaultFlags, VaultId, VaultWriter,
    },
    vfs, Error, Result, Timestamp,
};

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use tokio::sync::RwLock;

#[cfg(feature = "archive")]
use crate::account::archive::RestoreTargets;

/// Manages multiple folders loaded into memory and mirrored to disc.
pub struct FolderStorage {
    /// State of this storage.
    state: LocalState,

    /// Directories for file storage.
    paths: Arc<UserPaths>,

    /// Search index.
    pub(super) index: AccountSearch,

    /// Folder event logs.
    cache: HashMap<VaultId, FolderEventLog>,
}

impl FolderStorage {
    /// Create a new local provider for an account with the given
    /// identifier.
    pub async fn new(
        id: impl AsRef<str>,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            UserPaths::data_dir().map_err(|_| Error::NoCache)?
        };

        let dirs = UserPaths::new(data_dir, id);
        Self::new_paths(Arc::new(dirs)).await
    }

    /// Create new node cache backed by files on disc.
    async fn new_paths(paths: Arc<UserPaths>) -> Result<FolderStorage> {
        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            ));
        }

        paths.ensure().await?;

        Ok(Self {
            state: LocalState::new(true),
            cache: Default::default(),
            paths,
            index: AccountSearch::new(),
        })
    }

    /// Search index reference.
    pub fn index(&self) -> &AccountSearch {
        &self.index
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> &mut AccountSearch {
        &mut self.index
    }

    /// Get the event log cache.
    pub fn cache(&self) -> &HashMap<VaultId, FolderEventLog> {
        &self.cache
    }

    /// Get the mutable event log cache.
    pub fn cache_mut(&mut self) -> &mut HashMap<VaultId, FolderEventLog> {
        &mut self.cache
    }

    /// Find a summary in this storage.
    pub fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        self.state.find_vault(vault)
    }

    /// Find a summary in this storage.
    pub fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.state.find(predicate)
    }

    /// Get the computed storage directories for the provider.
    pub fn paths(&self) -> Arc<UserPaths> {
        Arc::clone(&self.paths)
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        // Find the id of an archive folder
        let summaries = {
            let summaries = self.folders();
            let mut archive: Option<VaultId> = None;
            for summary in summaries {
                if summary.flags().is_archive() {
                    archive = Some(*summary.id());
                    break;
                }
            }
            let mut writer = self.index.search_index.write().await;
            writer.set_archive_id(archive);
            summaries
        };
        let folders = summaries.to_vec();
        Ok((self.build_search_index(keys).await?, folders))
    }

    /// Build the search index for all folders.
    pub async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        // Clear search index first
        self.index.clear().await;

        for (summary, key) in &keys.0 {
            // Must open the vault so the provider state unlocks
            // the vault
            self.open_vault(summary, key).await?;

            let keeper = self.current().unwrap();
            self.index.add_folder(&keeper).await?;

            /*
            // Add the vault meta data to the search index
            writer.create_search_index().await?;
            */

            // Close the vault as we are done for now
            self.close_vault();
        }

        Ok(self.index.document_count().await)
    }

    /// Load a vault, unlock it and set it as the current vault.
    pub async fn open_vault(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<ReadEvent> {
        let vault_path = self.vault_path(summary);
        let vault = if self.state.mirror() {
            if !vfs::try_exists(&vault_path).await? {
                let vault = self.reduce_event_log(summary).await?;
                let buffer = encode(&vault).await?;
                self.write_vault_file(summary, &buffer).await?;
                vault
            } else {
                let buffer = vfs::read(&vault_path).await?;
                let vault: Vault = decode(&buffer).await?;
                vault
            }
        } else {
            self.reduce_event_log(summary).await?
        };

        self.state.open_vault(key, vault, vault_path).await?;
        Ok(ReadEvent::ReadVault)
    }

    /// Import the vaults for a new account.
    pub async fn import_new_account(
        &mut self,
        account: &NewAccount,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        events.push(Event::CreateAccount(AuditEvent::new(
            EventKind::CreateAccount,
            account.address.clone(),
            None,
        )));

        // Save the default vault
        let buffer = encode(&account.default_folder).await?;
        let (event, summary) = self
            .upsert_vault_buffer(
                buffer,
                account.folder_keys.find(account.default_folder.id()),
            )
            .await?;
        events.push(Event::Write(*summary.id(), event));

        if let Some(archive_vault) = &account.archive {
            let buffer = encode(archive_vault).await?;
            let (event, summary) = self
                .import_vault(
                    buffer,
                    account.folder_keys.find(archive_vault.id()),
                )
                .await?;
            events.push(Event::Write(*summary.id(), event));
        }

        if let Some(authenticator_vault) = &account.authenticator {
            let buffer = encode(authenticator_vault).await?;
            let (event, summary) = self
                .import_vault(
                    buffer,
                    account.folder_keys.find(authenticator_vault.id()),
                )
                .await?;
            events.push(Event::Write(*summary.id(), event));
        }

        if let Some(contact_vault) = &account.contacts {
            let buffer = encode(contact_vault).await?;
            let (event, summary) = self
                .import_vault(
                    buffer,
                    account.folder_keys.find(contact_vault.id()),
                )
                .await?;
            events.push(Event::Write(*summary.id(), event));
        }

        Ok(events)
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    #[cfg(feature = "archive")]
    pub async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
    ) -> Result<()> {
        let RestoreTargets { vaults, .. } = targets;

        // We may be restoring vaults that do not exist
        // so we need to update the cache
        let summaries = vaults
            .iter()
            .map(|(_, v)| v.summary().clone())
            .collect::<Vec<_>>();
        self.load_caches(&summaries).await?;

        for (buffer, vault) in vaults {
            // Prepare a fresh log of event log events
            let mut event_log_events = Vec::new();
            let create_vault = WriteEvent::CreateVault(buffer.clone());
            event_log_events.push(create_vault);

            self.update_vault(vault.summary(), vault, event_log_events)
                .await?;

            // Refresh the in-memory and disc-based mirror
            self.refresh_vault(vault.summary(), None).await?;
        }

        Ok(())
    }

    /// Get the path to a event log file.
    pub fn event_log_path(&self, summary: &Summary) -> PathBuf {
        self.paths.event_log_path(summary.id().to_string())
    }

    /// Get the path to a vault file.
    pub fn vault_path(&self, summary: &Summary) -> PathBuf {
        self.paths.vault_path(summary.id().to_string())
    }

    /// Get the folder summaries for this storage.
    pub fn folders(&self) -> &[Summary] {
        self.state.summaries()
    }

    /// Reference to the currently open folder.
    pub fn current_folder(&self) -> Option<&Summary> {
        self.current().map(|g| g.summary())
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.state.current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state.current_mut()
    }

    /// Create new patch and event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()> {
        let event_log_path = self.event_log_path(summary);
        let mut event_log =
            FolderEventLog::new_folder(&event_log_path).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.truncate().await?;

            let (vault, events) = EventReducer::split(vault).await?;
            event_log.apply(events.iter().collect()).await?;
        }
        event_log.load_tree().await?;

        self.cache_mut().insert(*summary.id(), event_log);
        Ok(())
    }

    /// Prepare to receive data for a new vault by
    /// creating an empty event log file on disc
    /// and adding the target to the list of vaults
    /// being managed by this local provider.
    pub async fn prepare_vault(&mut self, summary: Summary) -> Result<()> {
        // Add to our cache of managed vaults
        self.create_cache_entry(&summary, None).await?;

        // Add to the state of managed vaults
        self.state.add_summary(summary);
        Ok(())
    }

    /// Refresh the in-memory vault from the contents
    /// of the current event log file.
    ///
    /// If a new access key is given and the target
    /// folder is the currently open folder then the
    /// in-memory `Gatekeeper` is updated to use the new
    /// access key.
    pub async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_key: Option<&AccessKey>,
    ) -> Result<()> {
        let vault = self.reduce_event_log(summary).await?;

        // Rewrite the on-disc version if we are mirroring
        if self.state.mirror() {
            let buffer = encode(&vault).await?;
            self.write_vault_file(summary, &buffer).await?;
        }

        let index = self.index.search();
        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
                /*
                // Update the in-memory version
                let new_key = if let Some(new_key) = new_key {
                    if let Some(salt) = vault.salt() {
                        match new_key {
                            AccessKey::Password(password) => {
                                let salt = KeyDerivation::parse_salt(salt)?;
                                let deriver = vault.deriver();
                                let derived_private_key = deriver.derive(
                                    &password,
                                    &salt,
                                    keeper.vault().seed(),
                                )?;
                                Some(PrivateKey::Symmetric(
                                    derived_private_key,
                                ))
                            }
                            AccessKey::Identity(id) => {
                                Some(PrivateKey::Asymmetric(id.clone()))
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                */

                Self::replace_vault(index, keeper, vault, new_key).await?;
            }
        }
        Ok(())
    }

    /// Replace a vault in a gatekeeper and update the
    /// search index if the access key for the vault is
    /// available.
    async fn replace_vault(
        index: Arc<RwLock<SearchIndex>>,
        keeper: &mut Gatekeeper,
        vault: Vault,
        new_key: Option<&AccessKey>,
    ) -> Result<()> {
        let existing_keys = vault.keys().collect::<HashSet<_>>();

        keeper.lock();
        keeper.replace_vault(vault.clone()).await?;

        if let Some(key) = new_key {
            keeper.unlock(key).await?;

            let updated_keys = keeper.vault().keys().collect::<HashSet<_>>();
            let mut writer = index.write().await;

            for added_key in updated_keys.difference(&existing_keys) {
                if let Some((meta, secret, _)) = keeper
                    .read(added_key /*, Some(&vault), derived_key*/)
                    .await?
                {
                    writer.add(keeper.id(), added_key, &meta, &secret);
                }
            }

            for deleted_key in existing_keys.difference(&updated_keys) {
                writer.remove(keeper.id(), deleted_key);
            }

            for maybe_updated in updated_keys.union(&existing_keys) {
                if let (
                    Some(VaultCommit(existing_hash, _)),
                    Some(VaultCommit(updated_hash, _)),
                ) = (
                    keeper.vault().get(maybe_updated),
                    vault.get(maybe_updated),
                ) {
                    if existing_hash != updated_hash {
                        if let Some((meta, secret, _)) = keeper
                            .read(
                                maybe_updated,
                                //Some(&vault),
                                //derived_key,
                            )
                            .await?
                        {
                            writer.update(
                                keeper.id(),
                                maybe_updated,
                                &meta,
                                &secret,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Write the buffer for a vault to disc.
    async fn write_vault_file(
        &self,
        summary: &Summary,
        buffer: impl AsRef<[u8]>,
    ) -> Result<()> {
        let vault_path = self.vault_path(&summary);
        vfs::write(vault_path, buffer.as_ref()).await?;
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache().get(summary.id()).is_none() {
                self.create_cache_entry(summary, None).await?;
            }
        }
        Ok(())
    }

    /// Close the current open vault.
    pub fn close_vault(&mut self) {
        self.state.close_vault();
    }

    /// Get a reference to the commit tree for an event log file.
    pub fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache
            .get(summary.id())
            .map(|event_log| event_log.tree())
    }

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current().map(|c| c.id().clone());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_vault();
            }
        }

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        // Remove from the state of managed vaults
        self.state.remove_summary(summary);

        Ok(())
    }

    /// Create a new account or vault.
    pub async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
        is_account: bool,
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        let key = if let Some(key) = key {
            key
        } else {
            let (passphrase, _) = generate_passphrase()?;
            AccessKey::Password(passphrase)
        };

        let mut builder = VaultBuilder::new();
        if let Some(name) = name {
            builder = builder.public_name(name);
        }
        if is_account {
            builder = builder.flags(VaultFlags::DEFAULT);
        }
        let vault = match &key {
            AccessKey::Password(password) => {
                builder.password(password.clone(), None).await?
            }
            AccessKey::Identity(id) => {
                builder.shared(id, vec![], true).await?
            }
        };

        let buffer = encode(&vault).await?;

        let summary = vault.summary().clone();

        if self.state.mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault)).await?;

        Ok((buffer, key, summary))
    }

    /// Import a vault buffer into an existing account.
    ///
    /// If a vault with the same identifier already exists
    /// it is overwritten.
    pub async fn import_vault(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: Option<&AccessKey>,
    ) -> Result<(WriteEvent, Summary)> {
        self.upsert_vault_buffer(buffer, key).await
    }

    /// Remove a vault file and event log file.
    pub async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Remove the local event log file
        let event_log_path = self.event_log_path(summary);
        if vfs::try_exists(&event_log_path).await? {
            vfs::remove_file(&event_log_path).await?;
        }
        Ok(())
    }

    /// Get the account status.
    pub async fn account_status(&mut self) -> Result<AccountStatus> {
        let summaries = self.state.summaries();
        let mut proofs = HashMap::new();
        for summary in summaries {
            let event_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let last_commit =
                event_log.last_commit().await?.ok_or(Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            proofs.insert(*summary.id(), (last_commit, head));
        }
        Ok(AccountStatus {
            exists: true,
            proofs,
        })
    }

    /// Create a new account and default login vault.
    pub async fn create_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        self.create_vault_or_account(name, key, true).await
    }

    /// Create a new vault.
    pub async fn create_vault(
        &mut self,
        name: String,
        key: Option<AccessKey>,
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        self.create_vault_or_account(Some(name), key, false).await
    }

    /// Create or update a vault.
    async fn upsert_vault_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: Option<&AccessKey>,
    ) -> Result<(WriteEvent, Summary)> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let exists = self.find(|s| s.id() == vault.id()).is_some();
        let summary = vault.summary().clone();

        if exists {
            // Clean entries from the search index
            self.index
                .remove_folder_from_search_index(summary.id())
                .await;
        }

        // Always write out the updated buffer
        if self.state.mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        if !exists {
            // Add the summary to the vaults we are managing
            self.state.add_summary(summary.clone());
        }

        if let Some(key) = key {
            // Ensure the imported secrets are in the search index
            self.index.add_vault(vault.clone(), key).await?;
        }

        // Initialize the local cache for event log
        self.create_cache_entry(&summary, Some(vault)).await?;

        Ok(if !exists {
            (WriteEvent::CreateVault(buffer.as_ref().to_owned()), summary)
        } else {
            (WriteEvent::UpdateVault(buffer.as_ref().to_owned()), summary)
        })
    }

    /// Update an existing vault by replacing it with a new vault.
    pub async fn update_vault(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent>,
    ) -> Result<()> {
        if self.state.mirror() {
            // Write the vault to disc
            let buffer = encode(vault).await?;
            self.write_vault_file(summary, &buffer).await?;
        }

        // Apply events to the event log
        let event_log = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        event_log.clear().await?;
        event_log.apply(events.iter().collect()).await?;

        Ok(())
    }

    /// Compact an event log file.
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_event_log, old_size, new_size) =
            event_log_file.compact().await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        *event_log_file = compact_event_log;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary, None).await?;

        Ok((old_size, new_size))
    }

    /// Load a vault by reducing it from the event log stored on disc.
    pub async fn reduce_event_log(
        &mut self,
        summary: &Summary,
    ) -> Result<Vault> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        Ok(EventReducer::new()
            .reduce(event_log_file)
            .await?
            .build()
            .await?)
    }

    /// Load vault summaries from the local disc.
    pub async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let storage = self.paths.vaults_dir();
        let mut summaries = Vec::new();
        let mut contents = vfs::read_dir(&storage).await?;
        while let Some(entry) = contents.next_entry().await? {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(path).await?;
                    if summary.flags().is_system() {
                        continue;
                    }
                    summaries.push(summary);
                }
            }
        }

        self.load_caches(&summaries).await?;
        self.state.set_summaries(summaries);
        Ok(self.folders())
    }

    /// Remove a vault.
    pub async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;

        self.index
            .remove_folder_from_search_index(summary.id())
            .await;

        Ok(())
    }

    /// Set the name of a vault.
    pub async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        // Log the event log event
        //
        let event = WriteEvent::SetVaultName(name.as_ref().to_owned());
        self.patch(summary, vec![event.clone()]).await?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.as_ref().to_owned());
            }
        }

        // Now update the in-memory name for the current selected vault
        if let Some(keeper) = self.current_mut() {
            if keeper.vault().id() == summary.id() {
                keeper.set_vault_name(name.as_ref().to_owned()).await?;
            }
        }

        // Update the vault on disc
        let vault_path = self.vault_path(summary);
        let vault_file = VaultWriter::open(&vault_path).await?;
        let mut access = VaultWriter::new(vault_path, vault_file)?;
        access.set_vault_name(name.as_ref().to_owned()).await?;

        Ok(event)
    }

    /// Apply events to the event log.
    pub async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<WriteEvent>,
    ) -> Result<()> {
        // Apply events to the event log file
        {
            let event_log = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            event_log.apply(events.iter().collect()).await?;
        }

        // Update the vault file on disc
        let vault = self.reduce_event_log(summary).await?;
        let buffer = encode(&vault).await?;
        self.write_vault_file(summary, &buffer).await?;

        Ok(())
    }

    /// Create a secret in the currently open vault.
    pub async fn create_secret(
        &mut self,
        id: SecretId,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        let index_doc = {
            let search = self.index.search();
            let index = search.read().await;
            index.prepare(summary.id(), &id, &meta, &secret)
        };

        let event = {
            let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper.create(id, meta, secret).await?
        };
        self.patch(&summary, vec![event.clone()]).await?;

        {
            let search = self.index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(event)
    }

    /// Read a secret in the currently open folder.
    pub async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let result =
            keeper.read(id).await?.ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open folder.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        secret_data.meta.touch();

        let index_doc = {
            let search = self.index.search();
            let mut index = search.write().await;
            // Must remove from the index before we
            // prepare a new document otherwise the
            // document would be stale as `prepare()`
            // and `commit()` are for new documents
            index.remove(summary.id(), id);

            index.prepare(
                summary.id(),
                id,
                secret_data.meta(),
                secret_data.secret(),
            )
        };

        let event = {
            let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper
                .update(id, secret_data.meta, secret_data.secret)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };
        self.patch(&summary, vec![event.clone()]).await?;

        {
            let search = self.index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<WriteEvent> {
        let summary = {
            let keeper = self.current().ok_or(Error::NoOpenVault)?;
            keeper.summary().clone()
        };

        let event = {
            let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
            keeper.delete(id).await?.ok_or(Error::SecretNotFound(*id))?
        };
        self.patch(&summary, vec![event.clone()]).await?;

        {
            let search = self.index.search();
            let mut writer = search.write().await;
            writer.remove(summary.id(), id);
        }

        Ok(event)
    }

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    pub async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        let (new_key, new_vault, event_log_events) =
            ChangePassword::new(vault, current_key, new_key, None)
                .build()
                .await?;

        self.update_vault(vault.summary(), &new_vault, event_log_events)
            .await?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_key)).await?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(&new_key).await?;
            }
        }

        Ok(new_key)
    }

    /// Verify an event log.
    pub async fn verify(&self, summary: &Summary) -> Result<()> {
        use crate::commit::event_log_commit_tree_file;
        let event_log_path = self.event_log_path(summary);
        event_log_commit_tree_file(&event_log_path, true, |_| {}).await?;
        Ok(())
    }

    /// Get the history of events for a vault.
    pub async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, Timestamp, WriteEvent)>> {
        let event_log = self
            .cache()
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let mut records = Vec::new();
        let mut it = event_log.iter().await?;
        while let Some(record) = it.next_entry().await? {
            let event = event_log.event_data(&record).await?;
            let commit = CommitHash(record.commit());
            let time = record.time().clone();
            records.push((commit, time, event));
        }
        Ok(records)
    }
}

/// Collection of in-memory vaults.
struct LocalState {
    /// Whether this state should mirror changes to disc.
    mirror: bool,
    /// Vaults managed by this state.
    summaries: Vec<Summary>,
    /// Currently selected in-memory vault.
    current: Option<Gatekeeper>,
}

impl LocalState {
    /// Create a new node state.
    pub fn new(mirror: bool) -> Self {
        Self {
            mirror,
            summaries: Default::default(),
            current: None,
        }
    }

    /// Determine if mirroring is enabled.
    fn mirror(&self) -> bool {
        self.mirror
    }

    /// Current in-memory vault.
    fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Mutable reference to the current in-memory vault.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Vault summaries.
    fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Mutable reference to the vault summaries.
    fn summaries_mut(&mut self) -> &mut [Summary] {
        self.summaries.as_mut_slice()
    }

    /// Set the summaries for this state.
    fn set_summaries(&mut self, summaries: Vec<Summary>) {
        self.summaries = summaries;
        self.summaries.sort();
    }

    /// Add a summary to this state.
    fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
    }

    /// Remove a summary from this state.
    fn remove_summary(&mut self, summary: &Summary) {
        let index =
            self.summaries.iter().position(|s| s.id() == summary.id());
        if let Some(index) = index {
            self.summaries.remove(index);
            self.summaries.sort();
        }
    }

    /// Find a summary in this state by reference.
    fn find_vault(&self, vault: &FolderRef) -> Option<&Summary> {
        match vault {
            FolderRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            FolderRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Find a summary in this state.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    /// Set the current folder and unlock it.
    async fn open_vault(
        &mut self,
        key: &AccessKey,
        vault: Vault,
        vault_path: PathBuf,
    ) -> Result<()> {
        let mut keeper = if self.mirror {
            let vault_file = VaultWriter::open(&vault_path).await?;
            let mirror = VaultWriter::new(vault_path, vault_file)?;
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };

        keeper
            .unlock(key)
            .await
            .map_err(|_| Error::VaultUnlockFail)?;
        self.current = Some(keeper);
        Ok(())
    }

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }
}
