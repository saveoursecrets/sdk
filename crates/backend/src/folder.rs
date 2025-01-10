//! Folder combines an access point with an event log.
use crate::event_log::BackendEventLog;
use crate::reducers::FolderReducer;
use crate::Error;
use crate::FolderEventLog as BackendFolderEventLog;
use crate::{AccessPoint, FolderEventLog, Result};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    events::EventLog,
    events::{EventRecord, ReadEvent, WriteEvent},
    VaultFlags,
};
use sos_core::{constants::EVENT_LOG_EXT, decode};
use sos_filesystem::{
    events::FolderEventLog as FsFolderEventLog, FileSystemAccessPoint,
    VaultFileWriter,
};
use sos_vault::Vault;
use sos_vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRow},
    SecretAccess, VaultCommit, VaultId, VaultMeta,
};
use sos_vfs as vfs;
use std::path::Path;
use std::{borrow::Cow, sync::Arc};
use tokio::sync::RwLock;

/// Folder is a combined vault and event log.
pub struct Folder {
    pub(crate) keeper: AccessPoint,
    events: Arc<RwLock<FolderEventLog>>,
}

impl Folder {
    /// Create a new folder from a vault file on disc.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    pub async fn new_fs(path: impl AsRef<Path>) -> Result<Self> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log =
            FsFolderEventLog::<Error>::new(events_path).await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        let vault = if needs_init {
            // For the client-side we must split the events
            // out but keep the existing vault data (not the head-only)
            // version so that the event log here will match what the
            // server will have when an account is first synced
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            let (_, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;
            event_log.apply(events.iter().collect()).await?;
            vault
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            vault
        };

        let mirror = VaultFileWriter::<Error>::new(path.as_ref()).await?;
        let keeper = FileSystemAccessPoint::<Error>::new_mirror(
            vault,
            Box::new(mirror),
        );

        Ok(Self::init(
            AccessPoint::FileSystem(keeper),
            BackendEventLog::FileSystem(event_log),
        ))
    }

    /// Load a folder event log from the given path.
    pub async fn new_fs_event_log(
        path: impl AsRef<Path>,
    ) -> Result<Arc<RwLock<BackendFolderEventLog>>> {
        let mut event_log =
            FsFolderEventLog::<Error>::new(path.as_ref().to_owned()).await?;
        event_log.load_tree().await?;
        Ok(Arc::new(RwLock::new(BackendFolderEventLog::FileSystem(
            event_log,
        ))))
    }

    /// Create a new folder.
    fn init(keeper: AccessPoint, events: FolderEventLog) -> Self {
        Self {
            keeper,
            events: Arc::new(RwLock::new(events)),
        }
    }

    /// Folder identifier.
    pub fn id(&self) -> &VaultId {
        self.keeper.id()
    }

    /// AccessPoint for this folder.
    pub fn keeper(&self) -> &AccessPoint {
        &self.keeper
    }

    /// Mutable access point for this folder.
    pub fn keeper_mut(&mut self) -> &mut AccessPoint {
        &mut self.keeper
    }

    /// Clone of the event log.
    pub fn event_log(&self) -> Arc<RwLock<FolderEventLog>> {
        Arc::clone(&self.events)
    }

    /// Unlock using the folder access key.
    pub async fn unlock(
        &mut self,
        key: &AccessKey,
    ) -> crate::Result<VaultMeta> {
        Ok(self.keeper.unlock(key).await?)
    }

    /// Lock the folder.
    pub fn lock(&mut self) {
        self.keeper.lock();
    }

    /// Create a secret.
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> crate::Result<WriteEvent> {
        let event = self.keeper.create_secret(secret_data).await?;
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> crate::Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        Ok(self.keeper.read_secret(id).await?)
    }

    /// Read the encrypted contents of a secret.
    pub async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> crate::Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        Ok(self.keeper.raw_secret(id).await?)
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> crate::Result<Option<WriteEvent>> {
        if let Some(event) =
            self.keeper.update_secret(id, secret_meta, secret).await?
        {
            let mut events = self.events.write().await;
            events.apply(vec![&event]).await?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Delete a secret and it's meta data.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) = self.keeper.delete_secret(id).await? {
            let mut events = self.events.write().await;
            events.apply(vec![&event]).await?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Set the name of the folder.
    pub async fn rename_folder(
        &mut self,
        name: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        self.keeper.set_vault_name(name.as_ref().to_owned()).await?;
        let event = WriteEvent::SetVaultName(name.as_ref().to_owned());
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Set the folder flags.
    pub async fn update_folder_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        self.keeper.set_vault_flags(flags.clone()).await?;
        let event = WriteEvent::SetVaultFlags(flags);
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Description of this folder.
    pub async fn description(&self) -> Result<String> {
        let meta = self.keeper.vault_meta().await?;
        Ok(meta.description().to_owned())
    }

    /// Set the description of this folder.
    pub async fn set_description(
        &mut self,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        let mut meta = self.keeper.vault_meta().await?;
        meta.set_description(description.as_ref().to_owned());
        self.set_meta(&meta).await
    }

    /// Set the folder meta data.
    pub async fn set_meta(&mut self, meta: &VaultMeta) -> Result<WriteEvent> {
        let event = self.keeper.set_vault_meta(meta).await?;
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Folder commit state.
    pub async fn commit_state(&self) -> Result<CommitState> {
        let event_log = self.events.read().await;
        Ok(event_log.tree().commit_state()?)
    }

    /// Folder root commit hash.
    pub async fn root_hash(&self) -> Result<CommitHash> {
        let event_log = self.events.read().await;
        Ok(event_log
            .tree()
            .root()
            .ok_or(sos_core::Error::NoRootCommit)?)
    }

    /// Apply events to the event log.
    pub async fn apply(&mut self, events: Vec<&WriteEvent>) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.apply(events).await?;
        Ok(())
    }

    /// Apply event records to the event log.
    pub async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.apply_records(records).await?;
        Ok(())
    }

    /// Clear events from the event log.
    pub async fn clear(&mut self) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.clear().await?;
        Ok(())
    }
}

impl From<Folder> for Vault {
    fn from(value: Folder) -> Self {
        value.keeper.into()
    }
}
