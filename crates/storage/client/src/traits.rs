//! Client storage implementations.
use crate::{
    AccessOptions, AccountPack, Error, NewFolderOptions, Result,
    StorageChangeEvent,
};
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use sos_backend::{
    compact::compact_folder, extract_vault, BackendTarget, DeviceEventLog,
    Folder, FolderEventLog,
};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode,
    events::{
        patch::FolderPatch, AccountEvent, DeviceEvent, Event, EventKind,
        EventLog, EventRecord, ReadEvent, WriteEvent,
    },
    AccountId, AuthenticationError, FolderRef, Paths, SecretId, StorageError,
    UtcDateTime, VaultCommit, VaultFlags, VaultId,
};
use sos_login::{DelegatedAccess, FolderKeys, Identity};
use sos_password::diceware::generate_passphrase;
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::{CreateSet, StorageEventLogs};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    BuilderCredentials, ChangePassword, SecretAccess, Summary, Vault,
    VaultBuilder,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

#[cfg(feature = "audit")]
use {
    sos_audit::{AuditData, AuditEvent},
    sos_backend::audit::append_audit_events,
};

#[cfg(feature = "files")]
use {crate::files::ExternalFileManager, sos_backend::FileEventLog};

pub(crate) mod private {
    /// Internal struct for sealed functions.
    #[derive(Copy, Clone)]
    pub struct Internal;
}

use private::Internal;

/// Common functions for all client storage traits.
pub trait ClientBaseStorage {
    /// Account identifier.
    fn account_id(&self) -> &AccountId;

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

    /// Backend target.
    fn backend_target(&self) -> &BackendTarget;

    /// Set the authenticated user.
    #[doc(hidden)]
    fn set_authenticated_user(&mut self, user: Option<Identity>, _: Internal);

    #[doc(hidden)]
    fn guard_authenticated(&self, _: Internal) -> Result<()> {
        if self.authenticated_user().is_none() {
            // panic!("not authenticated");
            return Err(AuthenticationError::NotAuthenticated.into());
        }
        Ok(())
    }
}

/// Device management for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientDeviceStorage:
    StorageEventLogs<Error = Error> + ClientBaseStorage
{
    /// Collection of trusted devices.
    fn devices(&self) -> &IndexSet<TrustedDevice>;

    /// Set the collection of trusted devices.
    #[doc(hidden)]
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>, _: Internal);

    /// List trusted devices.
    fn list_trusted_devices(&self) -> Vec<&TrustedDevice>;

    /// Patch the devices event log.
    async fn patch_devices_unchecked(
        &mut self,
        events: &[DeviceEvent],
    ) -> Result<()> {
        self.guard_authenticated(Internal)?;

        // Update the event log
        let device_log = self.device_log().await?;
        let mut event_log = device_log.write().await;
        event_log.apply(events).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.set_devices(devices, Internal);

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
            writer.apply(&[event]).await?;

            let reducer = DeviceReducer::new(&*writer);
            self.set_devices(reducer.reduce().await?, Internal);
        }

        Ok(())
    }
}

/// Vault management for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientVaultStorage {
    /// Write a vault to storage.
    #[doc(hidden)]
    async fn write_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>>;

    /// Write the login vault to storage.
    #[doc(hidden)]
    async fn write_login_vault(
        &self,
        vault: &Vault,
        _: Internal,
    ) -> Result<Vec<u8>>;

    /// Remove a vault.
    #[doc(hidden)]
    async fn remove_vault(
        &self,
        folder_id: &VaultId,
        _: Internal,
    ) -> Result<()>;

    /// Read folders from the storage.
    #[doc(hidden)]
    async fn read_vaults(&self, _: Internal) -> Result<Vec<Summary>>;

    /// In-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries(&self, _: Internal) -> &Vec<Summary>;

    /// Mutable in-memory collection of folder summaries
    /// managed by this storage.
    #[doc(hidden)]
    fn summaries_mut(&mut self, _: Internal) -> &mut Vec<Summary>;

    /// Add a summary to the in-memory storage.
    #[doc(hidden)]
    fn add_summary(&mut self, summary: Summary, token: Internal) {
        let summaries = self.summaries_mut(token);
        summaries.push(summary);
        summaries.sort();
    }

    /// Remove a summary from the in-memory storage.
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
}

/// Folder management for client storage.
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
    #[doc(hidden)]
    async fn new_folder(&self, vault: &Vault, _: Internal) -> Result<Folder>;

    /// Read a vault from the storage.
    async fn read_vault(&self, id: &VaultId) -> Result<Vault>;

    /// Read the login vault from the storage.
    async fn read_login_vault(&self) -> Result<Vault>;

    /// Read the device vault from the storage.
    async fn read_device_vault(&self) -> Result<Option<Vault>> {
        Ok(self
            .backend_target()
            .read_device_vault(self.account_id())
            .await?)
    }

    /// List the in-memory folders.
    fn list_folders(&self) -> &[Summary] {
        self.summaries(Internal).as_slice()
    }

    /// Currently open folder.
    fn current_folder(&self) -> Option<Summary>;

    /// Find a folder in this storage by reference.
    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary> {
        match vault {
            FolderRef::Name(name) => {
                self.summaries(Internal).iter().find(|s| s.name() == name)
            }
            FolderRef::Id(id) => {
                self.summaries(Internal).iter().find(|s| s.id() == id)
            }
        }
    }

    /// Find a folder in this storage using a predicate.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries(Internal).iter().find(predicate)
    }

    /// Initialize a folder from a collection of event records.
    ///
    /// If an event log exists for the folder identifer
    /// it is replaced with the new event records.
    ///
    /// A vault is created from the reduced collection of events
    /// and written to storage.
    #[doc(hidden)]
    async fn initialize_folder(
        &mut self,
        // folder_id: &VaultId,
        records: Vec<EventRecord>,
        _: Internal,
    ) -> Result<(Folder, Vault)> {
        // Prepare the vault
        let vault = {
            let vault = extract_vault(records.as_slice())
                .await?
                .ok_or(Error::NoVaultEvent)?;

            let folder = self.new_folder(&vault, Internal).await?;
            let event_log = folder.event_log();
            let mut event_log = event_log.write().await;
            event_log.clear().await?;
            event_log.apply_records(records).await?;

            let vault = FolderReducer::new()
                .reduce(&*event_log)
                .await?
                .build(true)
                .await?;

            self.write_vault(&vault, Internal).await?;

            vault
        };

        // NOTE: we should be able to just return the folder and vault
        // NOTE: above and not re-load here but this breaks the
        // NOTE: network_sync_recover_remote_folder test so we need
        // NOTE: to figure out why

        // Setup the folder access to the latest vault information
        // and load the merkle tree
        let folder = self.new_folder(&vault, Internal).await?;
        let event_log = folder.event_log();
        let mut event_log = event_log.write().await;
        event_log.load_tree().await?;

        Ok((folder, vault))
    }

    /// Create new in-memory folder entry.
    #[doc(hidden)]
    async fn create_folder_entry(
        &mut self,
        vault: Vault,
        reset_events: bool,
        creation_time: Option<&UtcDateTime>,
        _: Internal,
    ) -> Result<()> {
        let folder_id = *vault.id();
        let mut folder = self.new_folder(&vault, Internal).await?;

        // Reset the event log from the contents of the vault.
        //
        // Used when importing or upserting from vaults to overwrite
        // and existing event logs.
        if reset_events {
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

            // Must truncate the event log so that importing vaults
            // does not end up with multiple create vault events
            folder.clear().await?;
            folder.apply_records(records).await?;
        }

        self.folders_mut().insert(folder_id, folder);

        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    #[doc(hidden)]
    async fn load_caches(
        &mut self,
        folders: &[Summary],
        _: Internal,
    ) -> Result<()> {
        for folder in folders {
            // Ensure we don't overwrite existing data
            let folder_id = folder.id();
            if self.folders().get(folder_id).is_none() {
                let folder = Folder::new(
                    self.backend_target().clone(),
                    self.account_id(),
                    folder.id(),
                )
                .await?;
                self.folders_mut().insert(*folder_id, folder);
            }
        }
        Ok(())
    }

    /// Remove the local cache for a vault.
    #[doc(hidden)]
    fn remove_folder_entry(
        &mut self,
        folder_id: &VaultId,
        _: Internal,
    ) -> Result<()> {
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
        vault: &Vault,
        events: Vec<WriteEvent>,
    ) -> Result<Vec<u8>> {
        self.guard_authenticated(Internal)?;

        let buffer = self.write_vault(vault, Internal).await?;

        // Apply events to the event log
        let folder = self
            .folders_mut()
            .get_mut(vault.id())
            .ok_or(StorageError::FolderNotFound(*vault.id()))?;
        folder.clear().await?;
        folder.apply(events.as_slice()).await?;

        Ok(buffer)
    }

    /// Load a vault by reducing it from the event log stored on disc.
    #[doc(hidden)]
    async fn reduce_event_log(
        &mut self,
        folder_id: &VaultId,
        _: Internal,
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
    /// If a new access key is given and then the
    /// in-memory `AccessPoint` is updated to use the new
    /// access key.
    #[doc(hidden)]
    async fn refresh_vault(
        &mut self,
        folder_id: &VaultId,
        key: &AccessKey,
        _: Internal,
    ) -> Result<Vec<u8>> {
        let vault = self.reduce_event_log(folder_id, Internal).await?;
        let buffer = self.write_vault(&vault, Internal).await?;

        if let Some(folder) = self.folders_mut().get_mut(folder_id) {
            let access_point = folder.access_point();
            let mut access_point = access_point.lock().await;

            access_point.lock();
            access_point.replace_vault(vault.clone(), false).await?;
            access_point.unlock(key).await?;
        }

        Ok(buffer)
    }

    /// Read folders from storage and create the in-memory
    /// event logs for each folder.
    async fn load_folders(&mut self) -> Result<&[Summary]> {
        let summaries = self.read_vaults(Internal).await?;
        self.load_caches(&summaries, Internal).await?;
        *self.summaries_mut(Internal) = summaries;
        Ok(self.list_folders())
    }

    /// Remove a folder from memory.
    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        self.guard_authenticated(Internal)?;

        Ok(if self.find(|s| s.id() == folder_id).is_some() {
            self.remove_folder_entry(folder_id, Internal)?;
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
        self.guard_authenticated(Internal)?;

        for (folder_id, patch) in patches {
            let records: Vec<EventRecord> = patch.into();
            let (folder, vault) =
                self.initialize_folder(records, Internal).await?;

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
            self.remove_summary(summary.id(), Internal);
            self.add_summary(summary, Internal);
        }
        Ok(())
    }

    /// Compact an event log file.
    async fn compact_folder(
        &mut self,
        folder_id: &VaultId,
        key: &AccessKey,
    ) -> Result<AccountEvent> {
        self.guard_authenticated(Internal)?;

        {
            let folder = self
                .folders_mut()
                .get_mut(folder_id)
                .ok_or(StorageError::FolderNotFound(*folder_id))?;
            let event_log = folder.event_log();
            let mut log_file = event_log.write().await;

            compact_folder(folder_id, &mut *log_file).await?;
        }

        // Refresh in-memory vault and mirrored copy
        let buffer = self.refresh_vault(folder_id, key, Internal).await?;

        let account_event = AccountEvent::CompactFolder(*folder_id, buffer);

        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(&[account_event.clone()]).await?;

        Ok(account_event)
    }

    /// Set the name of a folder.
    async fn rename_folder(
        &mut self,
        folder_id: &VaultId,
        name: impl AsRef<str> + Send,
    ) -> Result<Event> {
        self.guard_authenticated(Internal)?;

        // Update the in-memory name.
        self.set_folder_name(folder_id, name.as_ref(), Internal)?;

        let folder = self
            .folders_mut()
            .get_mut(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;

        folder.rename_folder(name.as_ref()).await?;

        let account_event =
            AccountEvent::RenameFolder(*folder_id, name.as_ref().to_owned());

        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(&[account_event.clone()]).await?;

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
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<Event> {
        self.guard_authenticated(Internal)?;

        // Update the in-memory name.
        self.set_folder_flags(folder_id, flags.clone(), Internal)?;

        let folder = self
            .folders_mut()
            .get_mut(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;

        let event = folder.update_folder_flags(flags).await?;
        let event = Event::Write(*folder_id, event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(event)
    }

    /// Update the in-memory name for a folder.
    #[doc(hidden)]
    fn set_folder_name(
        &mut self,
        folder_id: &VaultId,
        name: impl AsRef<str>,
        _: Internal,
    ) -> Result<()> {
        if let Some(summary) = self
            .summaries_mut(Internal)
            .iter_mut()
            .find(|f| f.id() == folder_id)
        {
            summary.set_name(name.as_ref().to_owned());
        }
        Ok(())
    }

    /// Update the in-memory name for a folder.
    #[doc(hidden)]
    fn set_folder_flags(
        &mut self,
        folder_id: &VaultId,
        flags: VaultFlags,
        _: Internal,
    ) -> Result<()> {
        if let Some(summary) = self
            .summaries_mut(Internal)
            .iter_mut()
            .find(|f| f.id() == folder_id)
        {
            *summary.flags_mut() = flags;
        }
        Ok(())
    }

    /// Get the description for a folder.
    async fn description(&self, folder_id: &VaultId) -> Result<String> {
        self.guard_authenticated(Internal)?;

        let folder = self
            .folders()
            .get(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;
        Ok(folder.description().await?)
    }

    /// Set the description of the currently open folder.
    async fn set_description(
        &mut self,
        folder_id: &VaultId,
        description: impl AsRef<str> + Send,
    ) -> Result<WriteEvent> {
        self.guard_authenticated(Internal)?;

        let folder = self
            .folders_mut()
            .get_mut(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;
        Ok(folder.set_description(description).await?)
    }
}

/// Secret management for client storage.
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
        options: &AccessOptions,
    ) -> Result<(Summary, SecretMeta, Secret, ReadEvent)>;

    /// Update a secret in the currently open folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent>;

    /// Write a secret.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    #[doc(hidden)]
    async fn write_secret(
        &mut self,
        folder: &Summary,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
        _: Internal,
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
    async fn remove_secret(
        &mut self,
        id: &SecretId,
        options: &AccessOptions,
    ) -> Result<WriteEvent>;
}

/// Internal utility functions for event log management.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[doc(hidden)]
pub trait ClientEventLogStorage {
    /// Initialize the device event log.
    #[doc(hidden)]
    async fn initialize_device_log(
        &self,
        device: TrustedDevice,
        _: Internal,
    ) -> Result<(DeviceEventLog, IndexSet<TrustedDevice>)>;

    /// Initialize the file event log.
    #[cfg(feature = "files")]
    #[doc(hidden)]
    async fn initialize_file_log(&self, _: Internal) -> Result<FileEventLog>;

    /// Set the identity event log.
    #[doc(hidden)]
    fn set_identity_log(
        &mut self,
        log: Arc<RwLock<FolderEventLog>>,
        _: Internal,
    );

    /// Set the device event log.
    #[doc(hidden)]
    fn set_device_log(
        &mut self,
        log: Arc<RwLock<DeviceEventLog>>,
        _: Internal,
    );

    /// Set the file event log.
    #[cfg(feature = "files")]
    #[doc(hidden)]
    fn set_file_log(&mut self, log: Arc<RwLock<FileEventLog>>, _: Internal);
}

/// Account management for client storage.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ClientAccountStorage:
    StorageEventLogs<Error = Error>
    + ClientBaseStorage
    + ClientDeviceStorage
    + ClientFolderStorage
    + ClientSecretStorage
    + ClientEventLogStorage
{
    /// Rename the account.
    async fn rename_account(&mut self, account_name: String) -> Result<()> {
        let authenticated_user = self
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        authenticated_user.rename_account(account_name).await?;
        Ok(())
    }

    /// Import an account from a change set of event logs.
    ///
    /// Intended to be used during pairing to create a new
    /// account from a collection of patches.
    ///
    /// # Authentication
    ///
    /// Can be called when the storage is not authenticated.
    async fn import_account(
        &mut self,
        account_data: &CreateSet,
    ) -> Result<()>;

    /// List the secret ids for a folder.
    async fn list_secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<SecretId>>;

    /// Create a device vault from a buffer.
    ///
    /// Used during pairing enrollment to initialize
    /// a device vault received from the authorizing device.
    ///
    /// # Authentication
    ///
    /// Can be called when the storage is not authenticated.
    async fn create_device_vault(
        &mut self,
        device_vault: &[u8],
    ) -> Result<()>;

    /// Delete the account for this user.
    async fn delete_account(&self) -> Result<Event>;

    /// Set the storage as authenticated.
    async fn authenticate(
        &mut self,
        authenticated_user: Identity,
    ) -> Result<()> {
        // Note that attempting to access the identity of an authenticated
        // user is an error when not authenticated.
        let identity_log = authenticated_user.identity()?.event_log();
        let device = authenticated_user
            .identity()?
            .devices()?
            .current_device(None);
        self.set_identity_log(identity_log, Internal);

        let (device_log, devices) =
            self.initialize_device_log(device, Internal).await?;
        self.set_device_log(Arc::new(RwLock::new(device_log)), Internal);
        self.set_devices(devices, Internal);

        #[cfg(feature = "files")]
        {
            let file_log = self.initialize_file_log(Internal).await?;
            let file_log = Arc::new(RwLock::new(file_log));
            let file_password =
                authenticated_user.find_file_encryption_password().await?;

            self.set_external_file_manager(
                Some(ExternalFileManager::new(
                    self.paths().clone(),
                    file_log.clone(),
                    file_password,
                )),
                Internal,
            );
            self.set_file_log(file_log, Internal);
        }

        #[cfg(feature = "search")]
        {
            self.set_search_index(Some(AccountSearch::new()), Internal);
        }
        self.set_authenticated_user(Some(authenticated_user), Internal);

        Ok(())
    }

    /// Change the password for a folder.
    ///
    /// If the target folder is the currently selected folder
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<()> {
        self.guard_authenticated(Internal)?;

        let folder_id = vault.id();
        let (new_key, new_vault, event_log_events) =
            ChangePassword::new(vault, current_key, new_key, None)
                .build()
                .await?;

        let buffer = self.update_vault(&new_vault, event_log_events).await?;

        let account_event =
            AccountEvent::ChangeFolderPassword(*folder_id, buffer);

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.id(), &new_key, Internal).await?;

        if let Some(folder) = self.folders_mut().get_mut(vault.id()) {
            let access_point = folder.access_point();
            let mut access_point = access_point.lock().await;
            access_point.unlock(&new_key).await?;
        }

        // Save the new password
        self.authenticated_user_mut()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .save_folder_password(folder_id, new_key)
            .await?;

        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(&[account_event]).await?;

        Ok(())
    }

    /// Sign out the authenticated user.
    async fn sign_out(&mut self) -> Result<()> {
        if let Some(authenticated) = self.authenticated_user_mut() {
            tracing::debug!("client_storage::sign_out_identity");
            // Forget private identity information
            authenticated.sign_out().await?;
        }

        #[cfg(feature = "search")]
        {
            tracing::debug!("client_storage::drop_search_index");
            self.set_search_index(None, Internal);
        }

        #[cfg(feature = "files")]
        {
            tracing::debug!("client_storage::drop_external_file_manager");
            self.set_external_file_manager(None, Internal);
        }

        tracing::debug!("client_storage::drop_authenticated_user");
        self.set_authenticated_user(None, Internal);

        Ok(())
    }

    /// Import a login vault and generate the event but
    /// do not write the event to the account event log.
    ///
    /// This is used when merging account event logs to ensure
    /// the `AccountEvent::UpdateIdentity` event is not duplicated.
    ///
    /// Typically the handlers that update storage but don't append log
    /// events are declared in the storage implementation but the
    /// identity log is managed by the account so this must exist here.
    #[doc(hidden)]
    async fn import_login_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        self.guard_authenticated(Internal)?;

        let user = self
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;

        vault
            .summary()
            .flags()
            .contains(VaultFlags::IDENTITY)
            .then_some(())
            .ok_or_else(|| sos_login::Error::NotIdentityFolder)?;

        // Update the identity vault
        let buffer = self.write_login_vault(&vault, Internal).await?;

        // Update the events for the identity vault
        let identity = user.identity()?;
        let event_log = identity.event_log();
        let mut event_log = event_log.write().await;
        event_log.clear().await?;

        let (_, events) = FolderReducer::split::<Error>(vault).await?;
        event_log.apply(events.as_slice()).await?;

        Ok(AccountEvent::UpdateIdentity(buffer))
    }

    /// Unlock all folders.
    async fn unlock(&mut self, keys: &FolderKeys) -> Result<()> {
        self.guard_authenticated(Internal)?;

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
    ///
    /// # Authentication
    ///
    /// Can be called when the storage is not authenticated.
    async fn lock(&mut self) {
        for (_, folder) in self.folders_mut().iter_mut() {
            folder.lock().await;
        }
    }

    /// Unlock a folder.
    async fn unlock_folder(
        &mut self,
        folder_id: &VaultId,
        key: &AccessKey,
    ) -> Result<()> {
        self.guard_authenticated(Internal)?;

        let folder = self
            .folders_mut()
            .get_mut(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;
        folder.unlock(key).await?;
        Ok(())
    }

    /// Lock a folder.
    ///
    /// # Authentication
    ///
    /// Can be called when the storage is not authenticated.
    async fn lock_folder(&mut self, id: &VaultId) -> Result<()> {
        let folder = self
            .folders_mut()
            .get_mut(id)
            .ok_or(StorageError::FolderNotFound(*id))?;
        folder.lock().await;
        Ok(())
    }

    /// Create the data for a new account.
    ///
    /// # Authentication
    ///
    /// Can be called when the storage is not authenticated.
    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        let create_account = Event::CreateAccount(account.account_id.into());

        // Each folder import will create an audit event
        // but we want the create account to be in the audit
        // log before the folder create audit events
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

    /// Prepare a new folder.
    #[doc(hidden)]
    async fn prepare_folder(
        &mut self,
        mut options: NewFolderOptions,
        _: Internal,
    ) -> Result<(Vec<u8>, AccessKey, Summary)> {
        let key = if let Some(key) = options.key.take() {
            key
        } else {
            let (passphrase, _) = generate_passphrase()?;
            AccessKey::Password(passphrase)
        };

        let builder = VaultBuilder::new()
            .flags(options.flags.unwrap_or_default())
            .cipher(options.cipher.unwrap_or_default())
            .kdf(options.kdf.unwrap_or_default())
            .public_name(options.name);

        let vault = match &key {
            AccessKey::Password(password) => {
                builder
                    .build(BuilderCredentials::Password(
                        password.clone(),
                        None,
                    ))
                    .await?
            }
            AccessKey::Identity(id) => {
                builder
                    .build(BuilderCredentials::Shared {
                        owner: id,
                        recipients: vec![],
                        read_only: true,
                    })
                    .await?
            }
        };

        let summary = vault.summary().clone();
        let buffer = self.write_vault(&vault, Internal).await?;

        // Add the summary to the vaults we are managing
        self.add_summary(summary.clone(), Internal);

        // Initialize the local cache for the event log
        self.create_folder_entry(vault, true, None, Internal)
            .await?;

        self.unlock_folder(summary.id(), &key).await?;

        Ok((buffer, key, summary))
    }

    /// Create a new folder.
    async fn create_folder(
        &mut self,
        options: NewFolderOptions,
    ) -> Result<(Vec<u8>, AccessKey, Summary, AccountEvent)> {
        self.guard_authenticated(Internal)?;

        let (buf, key, summary) =
            self.prepare_folder(options, Internal).await?;

        let account_event =
            AccountEvent::CreateFolder(*summary.id(), buf.clone());
        let account_log = self.account_log().await?;
        let mut account_log = account_log.write().await;
        account_log.apply(&[account_event.clone()]).await?;

        // Must save the folder access key
        self.authenticated_user_mut()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .save_folder_password(summary.id(), key.clone())
            .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok((buf, key, summary, account_event))
    }

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
        apply_event: bool,
    ) -> Result<Vec<Event>> {
        self.guard_authenticated(Internal)?;

        // Remove the files
        self.remove_vault(folder_id, Internal).await?;

        // Remove local state
        self.remove_folder_entry(folder_id, Internal)?;

        let mut events = Vec::new();

        #[cfg(feature = "files")]
        {
            let mut file_events = self
                .external_file_manager_mut()
                .ok_or_else(|| AuthenticationError::NotAuthenticated)?
                .delete_folder_files(folder_id)
                .await?;

            let file_log = self.file_log().await?;
            let mut writer = file_log.write().await;
            writer.apply(file_events.as_slice()).await?;
            for event in file_events.drain(..) {
                events.push(Event::File(event));
            }
        }

        // Clean the search index
        #[cfg(feature = "search")]
        if let Some(index) = self.search_index_mut() {
            index.remove_folder(folder_id).await;
        }

        self.authenticated_user_mut()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .remove_folder_password(folder_id)
            .await?;

        let account_event = AccountEvent::DeleteFolder(*folder_id);

        if apply_event {
            let account_log = self.account_log().await?;
            let mut account_log = account_log.write().await;
            account_log.apply(&[account_event.clone()]).await?;
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

    /// Restore a folder from an event log.
    async fn restore_folder(
        &mut self,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary> {
        self.guard_authenticated(Internal)?;

        let (mut folder, vault) =
            self.initialize_folder(records, Internal).await?;

        // Unlock the folder
        folder.unlock(key).await?;
        self.folders_mut().insert(*vault.id(), folder);

        let summary = vault.summary().to_owned();
        self.add_summary(summary.clone(), Internal);

        #[cfg(feature = "search")]
        if let Some(index) = self.search_index_mut() {
            // Ensure the imported secrets are in the search index
            index.add_vault(vault, key).await?;
        }

        Ok(summary)
    }

    /// Create or update a vault.
    #[doc(hidden)]
    async fn upsert_vault_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        creation_time: Option<&UtcDateTime>,
        _: Internal,
    ) -> Result<(bool, WriteEvent, Summary)> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let exists = self.find(|s| s.id() == vault.id()).is_some();
        let summary = vault.summary().clone();

        #[cfg(feature = "search")]
        if exists {
            if let Some(index) = self.search_index_mut() {
                // Clean entries from the search index
                index.remove_folder(summary.id()).await;
            }
        }

        self.write_vault(&vault, Internal).await?;

        if !exists {
            // Add the summary to the vaults we are managing
            self.add_summary(summary.clone(), Internal);
        } else {
            // Otherwise update with the new summary
            if let Some(existing) = self
                .summaries_mut(Internal)
                .iter_mut()
                .find(|s| s.id() == summary.id())
            {
                *existing = summary.clone();
            }
        }

        #[cfg(feature = "search")]
        if let Some(key) = key {
            if let Some(index) = self.search_index_mut() {
                // Ensure the imported secrets are in the search index
                index.add_vault(vault.clone(), key).await?;
            }
        }

        let event = vault.into_event().await?;

        // Initialize the local cache for event log
        self.create_folder_entry(vault, true, creation_time, Internal)
            .await?;

        // Must ensure the folder is unlocked
        if let Some(key) = key {
            self.unlock_folder(summary.id(), key).await?;
        }

        Ok((exists, event, summary))
    }

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    ///
    /// # Authentication
    ///
    /// Can be called when the account is not authenticated.
    async fn import_folder(
        &mut self,
        buffer: impl AsRef<[u8]> + Send,
        key: Option<&AccessKey>,
        apply_event: bool,
        creation_time: Option<&UtcDateTime>,
    ) -> Result<(Event, Summary)> {
        let (exists, write_event, summary) = self
            .upsert_vault_buffer(
                buffer.as_ref(),
                key,
                creation_time,
                Internal,
            )
            .await?;

        // If there is an existing folder
        // and we are overwriting then log the update
        // folder event
        let account_event = if exists {
            AccountEvent::UpdateFolder(
                *summary.id(),
                buffer.as_ref().to_owned(),
            )
        // Otherwise a create event
        } else {
            AccountEvent::CreateFolder(
                *summary.id(),
                buffer.as_ref().to_owned(),
            )
        };

        if apply_event {
            let account_log = self.account_log().await?;
            let mut account_log = account_log.write().await;
            account_log.apply(&[account_event.clone()]).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent =
                (self.account_id(), &account_event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok((Event::Folder(account_event, write_event), summary))
    }

    /// Get the history of events for a vault.
    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        self.guard_authenticated(Internal)?;

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
    ///
    /// # Authentication
    ///
    /// Can be called when the account is not authenticated.
    async fn identity_state(&self) -> Result<CommitState> {
        let identity_log = self.identity_log().await?;
        let reader = identity_log.read().await;
        Ok(reader.tree().commit_state()?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    ///
    /// # Authentication
    ///
    /// Can be called when the account is not authenticated.
    async fn commit_state(&self, folder_id: &VaultId) -> Result<CommitState> {
        let folder = self
            .folders()
            .get(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().commit_state()?)
    }

    /// External file manager.
    #[cfg(feature = "files")]
    fn external_file_manager(&self) -> Option<&ExternalFileManager>;

    /// Mutable external file manager.
    #[cfg(feature = "files")]
    fn external_file_manager_mut(
        &mut self,
    ) -> Option<&mut ExternalFileManager>;

    /// Set the external file manager.
    #[cfg(feature = "files")]
    #[doc(hidden)]
    fn set_external_file_manager(
        &mut self,
        file_manager: Option<ExternalFileManager>,
        _: Internal,
    );

    /// Search index reference.
    #[cfg(feature = "search")]
    fn search_index(&self) -> Option<&AccountSearch>;

    /// Mutable search index reference.
    #[cfg(feature = "search")]
    fn search_index_mut(&mut self) -> Option<&mut AccountSearch>;

    /// Set the search index.
    #[cfg(feature = "search")]
    #[doc(hidden)]
    fn set_search_index(&mut self, user: Option<AccountSearch>, _: Internal);

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        self.guard_authenticated(Internal)?;

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
            if let Some(index) = self.search_index() {
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
        self.guard_authenticated(Internal)?;

        use sos_core::AuthenticationError;

        {
            let index = self
                .search_index()
                .ok_or_else(|| AuthenticationError::NotAuthenticated)?;
            let search_index = index.search();
            let mut writer = search_index.write().await;

            // Clear search index first
            writer.remove_all();

            for (folder_id, key) in &keys.0 {
                if let Some(folder) = self.folders_mut().get_mut(folder_id) {
                    let access_point = folder.access_point();
                    let mut access_point = access_point.lock().await;
                    access_point.unlock(key).await?;
                    writer.add_folder(&*access_point).await?;
                }
            }
        }

        let count = if let Some(index) = self.search_index() {
            index.document_count().await
        } else {
            Default::default()
        };

        Ok(count)
    }
}
