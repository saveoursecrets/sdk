use crate::AccessOptions;
use crate::{
    filesystem::ClientFileStorage, ClientAccountStorage, ClientDeviceStorage,
    ClientFolderStorage, ClientSecretStorage, Error, Result,
    StorageChangeEvent,
};
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use sos_backend::{reducers::FolderReducer, Folder, StorageError};
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
use sos_core::{
    commit::{CommitHash, CommitState},
    SecretId, VaultId,
};
use sos_core::{
    crypto::AccessKey,
    decode, encode,
    events::{
        patch::FolderPatch, AccountEvent, Event, ReadEvent, WriteEvent,
    },
    AccountId, Paths, UtcDateTime,
};
use sos_sdk::{
    events::{EventLog, EventRecord},
    identity::FolderKeys,
};
use sos_sync::StorageEventLogs;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    ChangePassword, FolderRef, SecretAccess, Summary, Vault, VaultCommit,
    VaultFlags,
};
use std::{borrow::Cow, collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::FileEvent};

pub enum ClientStorage {
    /// Filesystem storage.
    FileSystem(ClientFileStorage),
    /// Database storage.
    Database(ClientFileStorage), // TODO!: db storage
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientSecretStorage for ClientStorage {
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!();
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'_, VaultCommit>, ReadEvent)>> {
        todo!();
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        todo!();
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!();
    }

    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        todo!();
    }

    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent> {
        todo!();
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientFolderStorage for ClientStorage {
    fn folders(&self) -> &HashMap<VaultId, Folder> {
        todo!();
    }

    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder> {
        todo!();
    }

    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        todo!();
    }

    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)> {
        todo!();
    }

    async fn load_folders(&mut self) -> Result<&[Summary]> {
        todo!(0;)
    }

    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        todo!();
    }

    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        todo!();
    }

    fn list_folders(&self) -> &[Summary] {
        todo!();
    }

    fn current_folder(&self) -> Option<Summary> {
        todo!();
    }

    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        todo!();
    }

    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent> {
        self.find(|s| s.id() == summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

        self.current = Some(summary.clone());
        Ok(ReadEvent::ReadVault)
    }

    fn close_folder(&mut self) {
        self.current = None;
    }

    async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()> {
        for (folder_id, patch) in patches {
            let records: Vec<EventRecord> = patch.into();
            let (folder, vault) =
                self.initialize_folder(&folder_id, records).await?;

            {
                let event_log = folder.event_log();
                let event_log = event_log.read().await;
                tracing::info!(
                  folder_id = %folder_id,
                  root = ?event_log.tree().root().map(|c| c.to_string()),
                  "import_folder_patch");
            }

            self.folders.insert(folder_id, folder);
            let summary = vault.summary().to_owned();
            self.add_summary(summary.clone());
        }
        Ok(())
    }

    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        {
            let folder = self
                .folders
                .get_mut(summary.id())
                .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
            let event_log = folder.event_log();
            let mut log_file = event_log.write().await;

            compact_folder(&mut *log_file).await?;
        }

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(summary, key).await?;

        let account_event =
            AccountEvent::CompactFolder(*summary.id(), buffer);

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(account_event)
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        let (mut folder, vault) =
            self.initialize_folder(folder_id, records).await?;

        // Unlock the folder
        folder.unlock(key).await?;
        self.folders.insert(*folder_id, folder);

        let summary = vault.summary().to_owned();
        self.add_summary(summary.clone());

        #[cfg(feature = "search")]
        if let Some(index) = self.index.as_mut() {
            // Ensure the imported secrets are in the search index
            index.add_vault(vault, key).await?;
        }

        Ok(summary)
    }

    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_name(summary, name.as_ref())?;

        let folder = self
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

        folder.rename_folder(name.as_ref()).await?;

        let account_event = AccountEvent::RenameFolder(
            *summary.id(),
            name.as_ref().to_owned(),
        );

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(Event::Account(account_event))
    }

    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_flags(summary, flags.clone())?;

        let folder = self
            .folders
            .get_mut(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;

        let event = folder.update_folder_flags(flags).await?;
        let event = Event::Write(*summary.id(), event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(event)
    }

    fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str>,
    ) -> Result<()> {
        for item in self.summaries.iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.as_ref().to_owned());
                break;
            }
        }
        Ok(())
    }

    fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()> {
        for item in self.summaries.iter_mut() {
            if item.id() == summary.id() {
                *item.flags_mut() = flags;
                break;
            }
        }
        Ok(())
    }

    async fn description(&self) -> Result<String> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.folders.get(summary.id()) {
            Ok(folder.description().await?)
        } else {
            Err(StorageError::CacheNotAvailable(*summary.id()).into())
        }
    }

    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        if let Some(folder) = self.folders.get_mut(summary.id()) {
            Ok(folder.set_description(description).await?)
        } else {
            Err(StorageError::CacheNotAvailable(*summary.id()).into())
        }
    }

    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        let (new_key, new_vault, event_log_events) =
            ChangePassword::new(vault, current_key, new_key, None)
                .build()
                .await?;

        let buffer = self
            .update_vault(vault.summary(), &new_vault, event_log_events)
            .await?;

        let account_event =
            AccountEvent::ChangeFolderPassword(*vault.id(), buffer);

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), &new_key).await?;

        if let Some(folder) = self.folders.get_mut(vault.id()) {
            let keeper = folder.keeper_mut();
            keeper.unlock(&new_key).await?;
        }

        let mut account_log = self.account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(new_key)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientDeviceStorage for ClientStorage {
    fn devices(&self) -> &IndexSet<TrustedDevice> {
        &self.devices
    }

    fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        self.devices.iter().collect()
    }

    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        // Update the event log
        let mut event_log = self.device_log.write().await;
        event_log.apply(events.iter().collect()).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

        #[cfg(feature = "audit")]
        {
            let audit_events = events
                .iter()
                .filter_map(|event| match event {
                    DeviceEvent::Trust(device) => Some(AuditEvent::new(
                        Default::default(),
                        EventKind::TrustDevice,
                        *self.account_id(),
                        Some(AuditData::Device(*device.public_key())),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !audit_events.is_empty() {
                append_audit_events(audit_events.as_slice()).await?;
            }
        }

        Ok(())
    }

    async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        let device =
            self.devices.iter().find(|d| d.public_key() == public_key);
        if device.is_some() {
            let event = DeviceEvent::Revoke(*public_key);

            let mut writer = self.device_log.write().await;
            writer.apply(vec![&event]).await?;

            let reducer = DeviceReducer::new(&*writer);
            self.devices = reducer.reduce().await?;
        }

        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ClientAccountStorage for ClientStorage {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        for (id, folder) in self.folders.iter_mut() {
            if let Some(key) = keys.find(id) {
                folder.unlock(key).await?;
            } else {
                tracing::error!(
                    folder_id = %id,
                    "unlock::no_folder_key",
                );
            }
        }
        Ok(())
    }

    async fn lock(&mut self) {
        for (_, folder) in self.folders.iter_mut() {
            folder.lock();
        }
    }

    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        let folder = self
            .folders
            .get_mut(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        folder.unlock(key).await?;
        Ok(())
    }

    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        let folder = self
            .folders
            .get_mut(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        folder.lock();
        Ok(())
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        let create_account = Event::CreateAccount(account.account_id.into());

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &create_account).into();
            append_audit_events(&[audit_event]).await?;
        }

        // Import folders
        for folder in &account.folders {
            let buffer = encode(folder).await?;
            let (event, _) =
                self.import_folder(buffer, None, true, None).await?;
            events.push(event);
        }

        events.insert(0, create_account);

        Ok(events)
    }

    async fn read_vault(&self, id: &VaultId) -> Result<Vault> {
        let buffer = self.read_vault_file(id).await?;
        Ok(decode(&buffer).await?)
    }

    /// Get the history of events for a vault.
    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let folder = self
            .folders
            .get(summary.id())
            .ok_or(StorageError::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let mut records = Vec::new();

        let stream = log_file.event_stream(false).await;
        pin_mut!(stream);

        while let Some(result) = stream.next().await {
            let (record, event) = result?;
            let commit = *record.commit();
            let time = record.time().clone();
            records.push((commit, time, event));
        }

        Ok(records)
    }

    /// Commit state of the identity folder.
    async fn identity_state(&self) -> Result<CommitState> {
        let reader = self.identity_log.read().await;
        Ok(reader.tree().commit_state()?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let folder = self
            .folders
            .get(summary.id())
            .ok_or_else(|| StorageError::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().commit_state()?)
    }

    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()> {
        let RestoreTargets { vaults, .. } = targets;

        // We may be restoring vaults that do not exist
        // so we need to update the cache
        let summaries = vaults
            .iter()
            .map(|(_, v)| v.summary().clone())
            .collect::<Vec<_>>();
        self.load_caches(&summaries).await?;

        for (_, vault) in vaults {
            // Prepare a fresh log of event log events
            let (vault, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;

            self.update_vault(vault.summary(), &vault, events).await?;

            // Refresh the in-memory and disc-based mirror
            let key = folder_keys
                .find(vault.id())
                .ok_or(Error::NoFolderPassword(*vault.id()))?;
            self.refresh_vault(vault.summary(), key).await?;
        }

        Ok(())
    }

    #[cfg(feature = "files")]
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    ) {
        self.file_password = file_password;
    }

    #[cfg(feature = "search")]
    fn index(&self) -> Result<&AccountSearch> {
        self.index.as_ref().ok_or(Error::NoSearchIndex)
    }

    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch> {
        self.index.as_mut().ok_or(Error::NoSearchIndex)
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        // Find the id of an archive folder
        let summaries = {
            let summaries = self.list_folders();
            let mut archive: Option<VaultId> = None;
            for summary in summaries {
                if summary.flags().is_archive() {
                    archive = Some(*summary.id());
                    break;
                }
            }
            if let Some(index) = &self.index {
                let mut writer = index.search_index.write().await;
                writer.set_archive_id(archive);
            }
            summaries
        };
        let folders = summaries.to_vec();
        Ok((self.build_search_index(keys).await?, folders))
    }

    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        {
            let index = self.index.as_ref().ok_or(Error::NoSearchIndex)?;
            let search_index = index.search();
            let mut writer = search_index.write().await;

            // Clear search index first
            writer.remove_all();

            for (summary, key) in &keys.0 {
                if let Some(folder) = self.folders.get_mut(summary.id()) {
                    let keeper = folder.keeper_mut();
                    keeper.unlock(key).await?;
                    writer.add_folder(keeper).await?;
                }
            }
        }

        let count = if let Some(index) = &self.index {
            index.document_count().await
        } else {
            Default::default()
        };

        Ok(count)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        todo!();
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        todo!();
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        todo!();
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        todo!();
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        todo!();
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        todo!();
    }
}
