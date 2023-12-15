//! Storage backed by the filesystem.
use crate::{
    constants::EVENT_LOG_EXT,
    crypto::AccessKey,
    decode,
    events::{
        DiscData, DiscLog, EventLogExt, EventReducer, FolderEventLog,
        MemoryData, MemoryFolderLog, MemoryLog, ReadEvent, WriteEvent,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Gatekeeper, Vault, VaultId, VaultMeta, VaultWriter,
    },
    vfs, Paths, Result,
};

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

/// Folder that writes events to disc.
pub type DiscFolder = Folder<FolderEventLog, DiscLog, DiscLog, DiscData>;

/// Folder that writes events to memory.
pub type MemoryFolder =
    Folder<MemoryFolderLog, MemoryLog, MemoryLog, MemoryData>;

/// Folder is a combined vault and event log.
pub struct Folder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    D: Clone,
{
    pub(crate) keeper: Gatekeeper,
    events: Option<Arc<RwLock<FolderEventLog>>>,
    marker: std::marker::PhantomData<(T, R, W, D)>,
}

impl<T, R, W, D> Folder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    D: Clone,
{
    /// Create a new folder.
    fn new(keeper: Gatekeeper, events: Option<FolderEventLog>) -> Self {
        Self {
            keeper,
            events: events.map(|e| Arc::new(RwLock::new(e))),
            marker: std::marker::PhantomData,
        }
    }

    /// Create a new folder from a vault buffer.
    ///
    /// Changes are not mirrored to disc and events are not logged.
    pub async fn new_buffer(buffer: impl AsRef<[u8]>) -> Result<Self> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let keeper = Gatekeeper::new(vault);
        Ok(Self::new(keeper, None))
    }

    /// Create a new folder from a vault file.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    pub async fn new_file(path: impl AsRef<Path>) -> Result<Self> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log = FolderEventLog::new_folder(events_path).await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        let vault = if needs_init {
            // For the client-side we must split the events
            // out but keep the existing vault data (not the head-only)
            // version so that the event log here will match what the
            // server will have when an account is first synced
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            let (_, events) = EventReducer::split(vault.clone()).await?;
            event_log.apply(events.iter().collect()).await?;
            vault
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            vault
        };

        let vault_file = VaultWriter::open(path.as_ref()).await?;
        let mirror = VaultWriter::new(path.as_ref(), vault_file)?;
        let keeper = Gatekeeper::new_mirror(vault, mirror);

        Ok(Self::new(keeper, Some(event_log)))
    }

    /// Load an identity vault event log from the given paths.
    pub async fn new_event_log(
        paths: &Paths,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let mut event_log =
            FolderEventLog::new_folder(paths.identity_events()).await?;
        event_log.load_tree().await?;
        Ok(Arc::new(RwLock::new(event_log)))
    }

    /// Clone of the event log.
    pub fn event_log(&self) -> Option<Arc<RwLock<FolderEventLog>>> {
        self.events.clone()
    }

    /// Folder identifier.
    pub fn id(&self) -> &VaultId {
        self.keeper.id()
    }

    /// Gatekeeper for this folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Unlock using the folder access key.
    pub async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        self.keeper.unlock(key).await
    }

    /// Lock the folder.
    pub fn lock(&mut self) {
        self.keeper.lock();
    }

    /// Create a secret.
    pub async fn create(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        let event = self.keeper.create(secret_data).await?;
        if let Some(events) = self.events.as_mut() {
            let mut events = events.write().await;
            events.apply(vec![&event]).await?;
        }
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        self.keeper.read(id).await
    }

    /// Update a secret.
    pub async fn update(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) =
            self.keeper.update(id, secret_meta, secret).await?
        {
            if let Some(events) = self.events.as_mut() {
                let mut events = events.write().await;
                events.apply(vec![&event]).await?;
            }
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Delete a secret and it's meta data.
    pub async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) = self.keeper.delete(id).await? {
            if let Some(events) = self.events.as_mut() {
                let mut events = events.write().await;
                events.apply(vec![&event]).await?;
            }
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}
