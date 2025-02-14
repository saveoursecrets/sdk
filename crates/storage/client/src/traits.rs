//! Client storage implementations.
use crate::{
    files::ExternalFileManager, AccessOptions, AccountPack, Error,
    NewFolderOptions, Result, StorageChangeEvent,
};
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use sos_audit::{AuditData, AuditEvent};
use sos_backend::{
    audit::append_audit_events, compact::compact_folder, Folder,
};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    device::{DevicePublicKey, TrustedDevice},
    encode,
    events::{
        patch::FolderPatch, AccountEvent, DeviceEvent, Event, EventKind,
        EventLog, EventRecord, ReadEvent, WriteEvent,
    },
    AccountId, FolderRef, Paths, SecretId, StorageError, UtcDateTime,
    VaultCommit, VaultFlags, VaultId,
};
use sos_login::{FolderKeys, Identity};
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::StorageEventLogs;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    SecretAccess, Summary, Vault,
};
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

pub(crate) mod private {
    /// Super trait for sealed traits.
    pub trait Sealed {}

    /// Internal struct for sealed functions.
    #[derive(Copy, Clone)]
    pub struct Internal;
}

use private::{Internal, Sealed};

/// Base client storage functions.
pub trait ClientBaseStorage {
    /// Account identifier.
    fn account_id(&self) -> &AccountId;
}

/// Device management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientDeviceStorage:
    StorageEventLogs<Error = Error> + ClientAccountStorage
{
    /// Collection of trusted devices.
    fn devices(&self) -> &IndexSet<TrustedDevice>;

    /// Set the collection of trusted devices.
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>);

    /// List trusted devices.
    fn list_trusted_devices(&self) -> Vec<&TrustedDevice>;

    /// Patch the devices event log.
    async fn patch_devices_unchecked(
        &mut self,
        events: Vec<DeviceEvent>,
    ) -> Result<()> {
        // Update the event log
        let device_log = self.device_log().await?;
        let mut event_log = device_log.write().await;
        event_log.apply(events.iter().collect()).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.set_devices(devices);

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

    /// Revoke trust in a device.
    async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        let device =
            self.devices().iter().find(|d| d.public_key() == public_key);
        if device.is_some() {
            let event = DeviceEvent::Revoke(*public_key);

            let device_log = self.device_log().await?;
            let mut writer = device_log.write().await;
            writer.apply(vec![&event]).await?;

            let reducer = DeviceReducer::new(&*writer);
            self.set_devices(reducer.reduce().await?);
        }

        Ok(())
    }
}

/// Vault management for client storage.
#[doc(hidden)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientVaultStorage: Sealed {
    /// Read a vault from the storage.
    async fn read_vault(&self, id: &VaultId) -> Result<Vault>;

    /// Write a vault to storage.
    async fn write_vault(&self, vault: &Vault) -> Result<Vec<u8>>;

    /// Remove a vault.
    async fn remove_vault(&self, folder_id: &VaultId) -> Result<()>;

    /// Read folders from the storage.
    async fn read_folders(&self) -> Result<Vec<Summary>>;

    /// In-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries(&self, _: Internal) -> &Vec<Summary>;

    /// Mutable in-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries_mut(&mut self, _: Internal) -> &mut Vec<Summary>;

    /// Add a summary to the in-memory stage.
    #[doc(hidden)]
    fn add_summary(&mut self, summary: Summary, token: Internal) {
        let summaries = self.summaries_mut(token);
        summaries.push(summary);
        summaries.sort();
    }

    /// Remove a summary from this storage.
    #[doc(hidden)]
    fn remove_summary(&mut self, folder_id: &VaultId, token: Internal) {
        if let Some(position) = self
            .summaries(token)
            .iter()
            .position(|s| s.id() == folder_id)
        {
            self.summaries_mut(token).remove(position);
            self.summaries_mut(token).sort();
        }
    }

    /// List the in-memory folders.
    fn list_folders(&self) -> &[Summary];

    /// Currently open folder.
    fn current_folder(&self) -> Option<Summary>;

    /// Find a folder in this storage by reference.
    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary>;

    /// Find a folder in this storage using a predicate.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool;
}

/// Folder management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientFolderStorage:
    StorageEventLogs<Error = Error> + ClientBaseStorage + ClientVaultStorage
{
    /// In-memory folders.
    fn folders(&self) -> &HashMap<VaultId, Folder>;

    /// Mutable in-memory folders.
    fn folders_mut(&mut self) -> &mut HashMap<VaultId, Folder>;

    /// Create a new folder.
    async fn new_folder(&self, folder_id: &VaultId) -> Result<Folder>;

    /// Initialize a folder from an event log.
    ///
    /// If an event log exists for the folder identifer
    /// it is replaced with the new event records.
    async fn initialize_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<(Folder, Vault)> {
        // Prepare the vault
        let vault = {
            let folder = self.new_folder(folder_id).await?;
            let event_log = folder.event_log();
            let mut event_log = event_log.write().await;
            event_log.clear().await?;
            event_log.apply_records(records).await?;

            let mut vault = FolderReducer::new()
                .reduce(&*event_log)
                .await?
                .build(true)
                .await?;

            let id = vault.header_mut().id_mut();
            *id = *folder_id;

            self.write_vault(&vault).await?;

            vault
        };

        // Setup the folder access to the latest vault information
        // and load the merkle tree
        let folder = self.new_folder(folder_id).await?;
        let event_log = folder.event_log();
        let mut event_log = event_log.write().await;
        event_log.load_tree().await?;

        Ok((folder, vault))
    }

    /// Create new in-memory folder entry.
    #[doc(hidden)]
    async fn create_folder_entry(
        &mut self,
        folder_id: &VaultId,
        vault: Option<Vault>,
        creation_time: Option<&UtcDateTime>,
        _: Internal,
    ) -> Result<()> {
        let mut folder = self.new_folder(folder_id).await?;

        if let Some(vault) = vault {
            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            folder.clear().await?;

            let (_, events) = FolderReducer::split::<Error>(vault).await?;

            let mut records = Vec::with_capacity(events.len());
            for event in events.iter() {
                records.push(EventRecord::encode_event(event).await?);
            }
            if let (Some(creation_time), Some(event)) =
                (creation_time, records.get_mut(0))
            {
                event.set_time(creation_time.to_owned());
            }
            folder.apply_records(records).await?;
        }

        self.folders_mut().insert(*folder_id, folder);

        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.folders().get(summary.id()).is_none() {
                self.create_folder_entry(summary.id(), None, None, Internal)
                    .await?;
            }
        }
        Ok(())
    }

    /// Remove the local cache for a vault.
    fn remove_folder_entry(&mut self, folder_id: &VaultId) -> Result<()> {
        let current_id = self.current_folder().map(|c| *c.id());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == folder_id {
                self.close_folder();
            }
        }

        // Remove from our cache of managed vaults
        self.folders_mut().remove(folder_id);

        // Remove from the state of managed vaults
        self.remove_summary(folder_id, Internal);

        Ok(())
    }

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent>,
    ) -> Result<Vec<u8>> {
        let buffer = self.write_vault(vault).await?;

        // Apply events to the event log
        let folder = self
            .folders_mut()
            .get_mut(summary.id())
            .ok_or(StorageError::FolderNotFound(*summary.id()))?;
        folder.clear().await?;
        folder.apply(events.iter().collect()).await?;

        Ok(buffer)
    }

    /// Load a vault by reducing it from the event log stored on disc.
    async fn reduce_event_log(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<Vault> {
        let event_log = self.folder_log(folder_id).await?;
        let log_file = event_log.read().await;
        Ok(FolderReducer::new()
            .reduce(&*log_file)
            .await?
            .build(true)
            .await?)
    }

    /// Refresh the in-memory vault from the contents
    /// of the current event log file.
    ///
    /// If a new access key is given and the target
    /// folder is the currently open folder then the
    /// in-memory `AccessPoint` is updated to use the new
    /// access key.
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<Vec<u8>> {
        let vault = self.reduce_event_log(summary.id()).await?;
        let buffer = self.write_vault(&vault).await?;

        if let Some(folder) = self.folders_mut().get_mut(summary.id()) {
            let access_point = folder.access_point();
            let mut access_point = access_point.lock().await;

            access_point.lock();
            access_point.replace_vault(vault.clone(), false).await?;
            access_point.unlock(key).await?;
        }

        Ok(buffer)
    }

    /// Create a new folder.
    async fn create_folder(
        &mut self,
        name: String,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)>;

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)>;

    /// Read folders from storage and create the in-memory
    /// event logs for each folder.
    async fn load_folders(&mut self) -> Result<&[Summary]> {
        let summaries = self.read_folders().await?;
        self.load_caches(&summaries).await?;
        *self.summaries_mut(Internal) = summaries;
        Ok(self.list_folders())
    }

    /// Remove a folder from memory.
    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        Ok(if self.find(|s| s.id() == folder_id).is_some() {
            self.remove_folder_entry(folder_id)?;
            true
        } else {
            false
        })
    }

    /// Mark a folder as the currently open folder.
    fn open_folder(&self, folder_id: &VaultId) -> Result<ReadEvent>;

    /// Close the current open folder.
    fn close_folder(&self);

    /// Create folders from a collection of folder patches.
    ///
    /// If the folders already exist they will be overwritten.
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

            self.folders_mut().insert(folder_id, folder);
            let summary = vault.summary().to_owned();
            self.add_summary(summary.clone(), Internal);
        }
        Ok(())
    }

    /// Compact an event log file.
    async fn compact_folder(
        &mut self,
        summary: &Summary,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        {
            let folder = self
                .folders_mut()
                .get_mut(summary.id())
                .ok_or(StorageError::FolderNotFound(*summary.id()))?;
            let event_log = folder.event_log();
            let mut log_file = event_log.write().await;

            compact_folder(&mut *log_file).await?;
        }

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(summary, key).await?;

        let account_event =
            AccountEvent::CompactFolder(*summary.id(), buffer);

        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        Ok(account_event)
    }

    /// Restore a folder from an event log.
    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary>;

    /// Set the name of a folder.
    async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_name(summary, name.as_ref())?;

        let folder = self
            .folders_mut()
            .get_mut(summary.id())
            .ok_or(StorageError::FolderNotFound(*summary.id()))?;

        folder.rename_folder(name.as_ref()).await?;

        let account_event = AccountEvent::RenameFolder(
            *summary.id(),
            name.as_ref().to_owned(),
        );

        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(vec![&account_event]).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(Event::Account(account_event))
    }

    /// Update the flags for a folder.
    async fn update_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<Event> {
        // Update the in-memory name.
        self.set_folder_flags(summary, flags.clone())?;

        let folder = self
            .folders_mut()
            .get_mut(summary.id())
            .ok_or(StorageError::FolderNotFound(*summary.id()))?;

        let event = folder.update_folder_flags(flags).await?;
        let event = Event::Write(*summary.id(), event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(event)
    }

    /// Update the in-memory name for a folder.
    fn set_folder_name(
        &mut self,
        summary: &Summary,
        name: impl AsRef<str> + Send,
    ) -> Result<()>;

    /// Update the in-memory name for a folder.
    fn set_folder_flags(
        &mut self,
        summary: &Summary,
        flags: VaultFlags,
    ) -> Result<()>;

    /// Get the description of the currently open folder.
    async fn description(&self) -> Result<String>;

    /// Set the description of the currently open folder.
    async fn set_description(
        &mut self,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent>;

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey>;
}

/// Secret management functions for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientSecretStorage {
    /// Create a secret in the currently open vault.
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Read the encrypted contents of a secret.
    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(VaultCommit, ReadEvent)>>;

    /// Read a secret in the currently open folder.
    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)>;

    /// Update a secret in the currently open folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Write a secret in the current open folder.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent>;

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent>;
}

/// Trait for client storage implementations.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientAccountStorage:
    StorageEventLogs<Error = Error> + ClientFolderStorage + ClientSecretStorage
{
    /// Authenticated user information.
    fn authenticated_user(&self) -> Option<&Identity>;

    /// Mutable authenticated user information.
    fn authenticated_user_mut(&mut self) -> Option<&mut Identity>;

    /// Determine if the storage is authenticated.
    fn is_authenticated(&self) -> bool {
        self.authenticated_user().is_some()
    }
    /// Computed storage paths.
    fn paths(&self) -> Arc<Paths>;

    /// Set the storage as authenticated.
    async fn authenticate(
        &mut self,
        authenticated_user: Identity,
    ) -> Result<()>;

    #[doc(hidden)]
    /// Remove the authenticated user and search index.
    fn drop_authenticated_state(&mut self, _: Internal);

    /// Sign out the authenticated user.
    async fn sign_out(&mut self) -> Result<()> {
        if let Some(authenticated) = self.authenticated_user_mut() {
            tracing::debug!("client_storage::sign_out_identity");
            // Forget private identity information
            authenticated.sign_out().await?;
        }

        tracing::debug!("client_storage::drop_authenticated_state");
        self.drop_authenticated_state(Internal);
        Ok(())
    }

    /// Import an identity vault and generate the event but
    /// do not write the event to the account event log.
    ///
    /// This is used when merging account event logs to ensure
    /// the `AccountEvent::UpdateIdentity` event is not duplicated.
    ///
    /// Typically the handlers that update storage but don't append log
    /// events are declared in the storage implementation but the
    /// identity log is managed by the account so this must exist here.
    #[doc(hidden)]
    async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent>;

    /// Unlock all folders.
    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        for (id, folder) in self.folders_mut().iter_mut() {
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

    /// Lock all folders.
    async fn lock(&mut self) {
        for (_, folder) in self.folders_mut().iter_mut() {
            folder.lock().await;
        }
    }

    /// Unlock a folder.
    async fn unlock_folder(
        &mut self,
        id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        let folder = self
            .folders_mut()
            .get_mut(id)
            .ok_or(StorageError::FolderNotFound(*id))?;
        folder.unlock(key).await?;
        Ok(())
    }

    /// Lock a folder.
    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        let folder = self
            .folders_mut()
            .get_mut(id)
            .ok_or(StorageError::FolderNotFound(*id))?;
        folder.lock().await;
        Ok(())
    }

    /// Create the data for a new account.
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

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        // Remove the files
        self.remove_vault(folder_id).await?;

        // Remove local state
        self.remove_folder_entry(folder_id)?;

        let mut events = Vec::new();

        #[cfg(feature = "files")]
        {
            let mut file_events = self
                .external_file_manager_mut()
                .delete_folder_files(folder_id)
                .await?;
            let file_log = self.file_log().await?;
            let mut writer = file_log.write().await;
            writer.apply(file_events.iter().collect()).await?;
            for event in file_events.drain(..) {
                events.push(Event::File(event));
            }
        }

        // Clean the search index
        #[cfg(feature = "search")]
        if let Some(index) = self.index_mut() {
            index.remove_folder(folder_id).await;
        }

        let account_event = AccountEvent::DeleteFolder(*folder_id);

        if apply_event {
            let account_log = self.account_log().await?;
            let mut account_log = account_log.write().await;
            account_log.apply(vec![&account_event]).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        events.insert(0, Event::Account(account_event));

        Ok(events)
    }

    /// Get the history of events for a vault.
    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        let folder = self
            .folders()
            .get(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;
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
        let identity_log = self.identity_log().await?;
        let reader = identity_log.read().await;
        Ok(reader.tree().commit_state()?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let folder = self
            .folders()
            .get(summary.id())
            .ok_or_else(|| StorageError::FolderNotFound(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().commit_state()?)
    }

    /// Restore vaults from an archive.
    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()>;

    /// External file manager.
    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> &ExternalFileManager;

    /// Mutable external file manager.
    #[cfg(feature = "files")]
    fn external_file_manager_mut(&mut self) -> &mut ExternalFileManager;

    /// Search index reference.
    #[cfg(feature = "search")]
    fn index(&self) -> Option<&AccountSearch>;

    /// Mutable search index reference.
    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Option<&mut AccountSearch>;

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
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
            if let Some(index) = self.index() {
                let mut writer = index.search_index.write().await;
                writer.set_archive_id(archive);
            }
            summaries
        };
        let folders = summaries.to_vec();
        Ok((self.build_search_index(keys).await?, folders))
    }

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount> {
        use sos_core::AuthenticationError;

        {
            let index = self
                .index()
                .ok_or_else(|| AuthenticationError::NotAuthenticated)?;
            let search_index = index.search();
            let mut writer = search_index.write().await;

            // Clear search index first
            writer.remove_all();

            for (summary, key) in &keys.0 {
                if let Some(folder) = self.folders_mut().get_mut(summary.id())
                {
                    let access_point = folder.access_point();
                    let mut access_point = access_point.lock().await;
                    access_point.unlock(key).await?;
                    writer.add_folder(&*access_point).await?;
                }
            }
        }

        let count = if let Some(index) = self.index() {
            index.document_count().await
        } else {
            Default::default()
        };

        Ok(count)
    }
}
