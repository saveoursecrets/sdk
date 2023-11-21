//! Storage provider backed by the local filesystem.
use sos_sdk::{
    account::{
        AccountStatus, ImportedAccount, NewAccount, RestoreTargets, UserPaths,
    },
    commit::{CommitHash, CommitTree},
    constants::VAULT_EXT,
    crypto::{AccessKey, KeyDerivation, PrivateKey},
    decode, encode,
    events::{
        AuditEvent, AuditLogFile, Event, EventKind, EventLogFile,
        EventReducer, ReadEvent, WriteEvent,
    },
    passwd::{diceware::generate_passphrase, ChangePassword},
    search::SearchIndex,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Gatekeeper, Header, Summary, Vault, VaultBuilder, VaultFlags,
        VaultId, VaultRef, VaultWriter,
    },
    vfs, Timestamp,
};

use std::{borrow::Cow, collections::HashMap, path::PathBuf, sync::Arc};

use tokio::sync::RwLock;

use crate::client::{Error, Result};

/// Local storage provider.
pub struct LocalProvider {
    /// State of this storage.
    state: LocalState,

    /// Directories for file storage.
    paths: Arc<UserPaths>,

    /// Cache for event log and patch providers.
    cache: HashMap<VaultId, EventLogFile>,

    /// Audit log for this provider.
    audit_log: Arc<RwLock<AuditLogFile>>,
}

impl LocalProvider {
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
    async fn new_paths(paths: Arc<UserPaths>) -> Result<LocalProvider> {
        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            ));
        }

        paths.ensure().await?;

        let audit_log = Arc::new(RwLock::new(
            AuditLogFile::new(paths.audit_file()).await?,
        ));

        Ok(Self {
            state: LocalState::new(true),
            cache: Default::default(),
            paths,
            audit_log,
        })
    }

    /// Get the event log cache.
    pub fn cache(&self) -> &HashMap<VaultId, EventLogFile> {
        &self.cache
    }

    /// Get the mutable event log cache.
    pub fn cache_mut(&mut self) -> &mut HashMap<VaultId, EventLogFile> {
        &mut self.cache
    }

    /// Get the state for this storage provider.
    pub fn state(&self) -> &LocalState {
        &self.state
    }

    /// Get a mutable reference to the state for this storage provider.
    pub fn state_mut(&mut self) -> &mut LocalState {
        &mut self.state
    }

    /// Get the audit log for this provider.
    pub fn audit_log(&self) -> Arc<RwLock<AuditLogFile>> {
        Arc::clone(&self.audit_log)
    }

    /// Get the computed storage directories for the provider.
    pub fn paths(&self) -> Arc<UserPaths> {
        Arc::clone(&self.paths)
    }

    /// Load a vault, unlock it and set it as the current vault.
    pub async fn open_vault(
        &mut self,
        summary: &Summary,
        key: AccessKey,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<ReadEvent> {
        let vault_path = self.vault_path(summary);
        let vault = if self.state().mirror() {
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

        self.state_mut()
            .open_vault(key, vault, vault_path, index)
            .await?;
        Ok(ReadEvent::ReadVault)
    }

    /// Create the search index for the currently open vault.
    pub async fn create_search_index(&mut self) -> Result<()> {
        self.state_mut().create_search_index().await
    }

    /// Import the vaults for a new account.
    pub async fn import_new_account(
        &mut self,
        account: &NewAccount,
    ) -> Result<(ImportedAccount, Vec<Event<'static>>)> {
        let mut events = Vec::new();

        events.push(Event::CreateAccount(AuditEvent::new(
            EventKind::CreateAccount,
            account.address.clone(),
            None,
        )));

        // Save the default vault
        let buffer = encode(&account.default_vault).await?;

        let (event, summary) = self.upsert_vault_buffer(buffer).await?;
        events.push(Event::Write(*summary.id(), event.into_owned()));

        let archive = if let Some(archive_vault) = &account.archive {
            let buffer = encode(archive_vault).await?;
            let (event, summary) = self.import_vault(buffer).await?;
            events.push(Event::Write(*summary.id(), event.into_owned()));
            Some(summary)
        } else {
            None
        };

        let authenticator =
            if let Some(authenticator_vault) = &account.authenticator {
                let buffer = encode(authenticator_vault).await?;
                let (event, summary) = self.import_vault(buffer).await?;
                events.push(Event::Write(*summary.id(), event.into_owned()));
                Some(summary)
            } else {
                None
            };

        let contacts = if let Some(contact_vault) = &account.contacts {
            let buffer = encode(contact_vault).await?;
            let (event, summary) = self.import_vault(buffer).await?;
            events.push(Event::Write(*summary.id(), event.into_owned()));
            Some(summary)
        } else {
            None
        };

        Ok((
            ImportedAccount {
                summary,
                archive,
                authenticator,
                contacts,
            },
            events,
        ))
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
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
            let create_vault = WriteEvent::CreateVault(Cow::Borrowed(buffer));
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

    /// Get the vault summaries for this storage.
    pub fn vaults(&self) -> &[Summary] {
        self.state().summaries()
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.state().current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state_mut().current_mut()
    }

    /// Create new patch and event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()> {
        let event_log_path = self.event_log_path(summary);
        let mut event_log = EventLogFile::new(&event_log_path).await?;

        if let Some(vault) = &vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            event_log.truncate().await?;

            let encoded = encode(vault).await?;
            let event = WriteEvent::CreateVault(Cow::Owned(encoded));
            event_log.append_event(event).await?;
        }
        event_log.load_tree().await?;

        self.cache_mut().insert(*summary.id(), event_log);
        Ok(())
    }

    /// Add a summary to the in-memory cache of vaults.
    pub(super) async fn add_local_cache(
        &mut self,
        summary: Summary,
    ) -> Result<()> {
        // Add to our cache of managed vaults
        self.create_cache_entry(&summary, None).await?;

        // Add to the state of managed vaults
        self.state_mut().add_summary(summary);
        Ok(())
    }

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current event log file.
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_key: Option<&AccessKey>,
    ) -> Result<()> {
        let vault = self.reduce_event_log(summary).await?;

        // Rewrite the on-disc version if we are mirroring
        if self.state().mirror() {
            let buffer = encode(&vault).await?;
            self.write_vault_file(summary, &buffer).await?;
        }

        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
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

                keeper.replace_vault(vault, new_key).await?;
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
        self.state_mut().close_vault();
    }

    /// Get a reference to the commit tree for an event log file.
    pub fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache
            .get(summary.id())
            .map(|event_log| event_log.tree())
    }

    /// Remove the local cache for a vault.
    pub(super) fn remove_local_cache(
        &mut self,
        summary: &Summary,
    ) -> Result<()> {
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
        self.state_mut().remove_summary(summary);

        Ok(())
    }

    /// Create a new account or vault.
    pub async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
        is_account: bool,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
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

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for event log and Patch
        self.create_cache_entry(&summary, Some(vault)).await?;

        let event = WriteEvent::CreateVault(Cow::Owned(buffer));
        Ok((event, key, summary))
    }

    /// Import a vault buffer into an existing account.
    ///
    /// If a vault with the same identifier already exists
    /// it is overwritten.
    pub async fn import_vault(
        &mut self,
        buffer: impl AsRef<[u8]>,
    ) -> Result<(WriteEvent<'static>, Summary)> {
        self.upsert_vault_buffer(buffer).await
    }

    /// Remove a vault file and event log file.
    pub async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::EVENT_LOG_DELETED_EXT;

        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Rename the local event log file so recovery is still possible
        let event_log_path = self.event_log_path(summary);
        if vfs::try_exists(&event_log_path).await? {
            let mut event_log_path_backup = event_log_path.clone();
            event_log_path_backup.set_extension(EVENT_LOG_DELETED_EXT);
            vfs::rename(event_log_path, event_log_path_backup).await?;
        }
        Ok(())
    }

    /*
    /// Create a backup of a vault file.
    pub async fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vfs::try_exists(&vault_path).await? {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            vfs::rename(&vault_path, &vault_backup).await?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        Ok(())
    }
    */

    /// Get the account status.
    pub async fn account_status(&mut self) -> Result<AccountStatus> {
        let summaries = self.state.summaries();
        let mut proofs = HashMap::new();
        for summary in summaries {
            let event_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            proofs.insert(*summary.id(), event_log.tree().head()?);
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
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
        self.create_vault_or_account(name, key, true).await
    }

    /// Create a new vault.
    pub async fn create_vault(
        &mut self,
        name: String,
        key: Option<AccessKey>,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
        self.create_vault_or_account(Some(name), key, false).await
    }

    /// Create or update a vault.
    async fn upsert_vault_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
    ) -> Result<(WriteEvent<'static>, Summary)> {
        let vault: Vault = decode(buffer.as_ref()).await?;

        let exists = self.state().find(|s| s.id() == vault.id()).is_some();

        let summary = vault.summary().clone();

        // Always write out the updated buffer
        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        if !exists {
            // Add the summary to the vaults we are managing
            self.state_mut().add_summary(summary.clone());
        }

        // Initialize the local cache for event log
        self.create_cache_entry(&summary, Some(vault)).await?;

        Ok(if !exists {
            (
                WriteEvent::CreateVault(Cow::Owned(
                    buffer.as_ref().to_owned(),
                )),
                summary,
            )
        } else {
            (
                WriteEvent::UpdateVault(Cow::Owned(
                    buffer.as_ref().to_owned(),
                )),
                summary,
            )
        })
    }

    /// Update an existing vault by replacing it with a new vault.
    pub async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent<'a>>,
    ) -> Result<()> {
        if self.state().mirror() {
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
        event_log.apply(events, None).await?;

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
        self.state_mut().set_summaries(summaries);
        Ok(self.vaults())
    }

    /// Remove a vault.
    pub async fn remove_vault(
        &mut self,
        summary: &Summary,
    ) -> Result<WriteEvent<'static>> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;

        Ok(WriteEvent::DeleteVault)
    }

    /// Set the name of a vault.
    pub async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<WriteEvent<'static>> {
        // Log the event log event
        let event =
            WriteEvent::SetVaultName(Cow::Borrowed(name)).into_owned();
        self.patch(summary, vec![event.clone()]).await?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }

        Ok(event)
    }

    /// Apply events to the event log.
    pub async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<WriteEvent<'static>>,
    ) -> Result<()> {
        // Apply events to the event log file
        {
            let event_log = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            event_log.apply(events, None).await?;
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
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.create(meta, secret).await?.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Read a secret in the currently open vault.
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

    /// Update a secret in the currently open vault.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretData,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        secret_data.meta.touch();
        let event = keeper
            .update(id, secret_data.meta, secret_data.secret)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event =
            keeper.delete(id).await?.ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
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
                keeper.unlock(new_key.clone()).await?;
            }
        }

        Ok(new_key)
    }

    /// Verify an event log.
    pub async fn verify(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::commit::event_log_commit_tree_file;
        let event_log_path = self.event_log_path(summary);
        event_log_commit_tree_file(&event_log_path, true, |_| {}).await?;
        Ok(())
    }

    /// Get the history of events for a vault.
    pub async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, Timestamp, WriteEvent<'_>)>> {
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

/// Manages the state of a node.
pub struct LocalState {
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
    pub fn mirror(&self) -> bool {
        self.mirror
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries_mut(&mut self) -> &mut [Summary] {
        self.summaries.as_mut_slice()
    }

    /// Set the summaries for this state.
    pub fn set_summaries(&mut self, summaries: Vec<Summary>) {
        self.summaries = summaries;
        self.summaries.sort();
    }

    /// Add a summary to this state.
    pub fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
    }

    /// Remove a summary from this state.
    pub fn remove_summary(&mut self, summary: &Summary) {
        let index =
            self.summaries.iter().position(|s| s.id() == summary.id());
        if let Some(index) = index {
            self.summaries.remove(index);
            self.summaries.sort();
        }
    }

    /// Find a summary in this state by reference.
    pub fn find_vault(&self, vault: &VaultRef) -> Option<&Summary> {
        match vault {
            VaultRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            VaultRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Find a summary in this state.
    pub fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    /// Set the current vault and unlock it.
    pub async fn open_vault(
        &mut self,
        key: AccessKey,
        vault: Vault,
        vault_path: PathBuf,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<()> {
        let mut keeper = if self.mirror {
            let vault_file = VaultWriter::open(&vault_path).await?;
            let mirror = VaultWriter::new(vault_path, vault_file)?;
            Gatekeeper::new_mirror(vault, mirror, index)
        } else {
            Gatekeeper::new(vault, index)
        };

        keeper
            .unlock(key)
            .await
            .map_err(|_| Error::VaultUnlockFail)?;
        self.current = Some(keeper);
        Ok(())
    }

    /// Add this vault to the search index.
    pub(crate) async fn create_search_index(&mut self) -> Result<()> {
        let keeper = self.current_mut().ok_or_else(|| Error::NoOpenVault)?;
        keeper.create_search_index().await?;
        Ok(())
    }

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    pub fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }
}
