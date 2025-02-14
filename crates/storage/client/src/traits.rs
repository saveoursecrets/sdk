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
pub trait ClientVaultStorage: private::Sealed {
    /// Read a vault from the storage.
    async fn read_vault(&self, id: &VaultId) -> Result<Vault>;

    /// Write a vault to storage.
    async fn write_vault(&self, vault: &Vault) -> Result<Vec<u8>>;

    /// Read folders from the storage.
    async fn read_folders(&self) -> Result<Vec<Summary>>;

    /// In-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries(&self, _: private::Internal) -> &Vec<Summary>;

    /// Mutable in-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries_mut(&mut self, _: private::Internal) -> &mut Vec<Summary>;

    /// Add a summary to the in-memory stage.
    #[doc(hidden)]
    fn add_summary(&mut self, summary: Summary, token: private::Internal) {
        let summaries = self.summaries_mut(token);
        summaries.push(summary);
        summaries.sort();
    }

    /// Remove a summary from this storage.
    #[doc(hidden)]
    fn remove_summary(
        &mut self,
        folder_id: &VaultId,
        token: private::Internal,
    ) {
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
    async fn load_folders(&mut self) -> Result<&[Summary]>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
        apply_event: bool,
    ) -> Result<Vec<Event>>;

    /// Remove a folder from memory.
    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool>;

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
    ) -> Result<()>;

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
    ) -> Result<Event>;

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
    fn drop_authenticated_state(&mut self, _: private::Internal);

    /// Sign out the authenticated user.
    async fn sign_out(&mut self) -> Result<()> {
        if let Some(authenticated) = self.authenticated_user_mut() {
            tracing::debug!("client_storage::sign_out_identity");
            // Forget private identity information
            authenticated.sign_out().await?;
        }

        tracing::debug!("client_storage::drop_authenticated_state");
        self.drop_authenticated_state(private::Internal);
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
