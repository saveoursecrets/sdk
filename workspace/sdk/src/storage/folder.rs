//! Storage backed by the filesystem.
use crate::{
    commit::{CommitState, Comparison},
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

use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[cfg(feature = "sync")]
use crate::sync::{CheckedPatch, FolderDiff};

/// Folder that writes events to disc.
pub type DiscFolder = Folder<FolderEventLog, DiscLog, DiscLog, DiscData>;

/// Folder that writes events to memory.
pub type MemoryFolder =
    Folder<MemoryFolderLog, MemoryLog, MemoryLog, MemoryData>;

/// Folder is a combined vault and event log.
pub struct Folder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    D: Clone + Send + Sync,
{
    pub(crate) keeper: Gatekeeper,
    events: Arc<RwLock<T>>,
    marker: std::marker::PhantomData<(R, W, D)>,
}

impl<T, R, W, D> Folder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    D: Clone + Send + Sync,
{
    /// Create a new folder.
    fn init(keeper: Gatekeeper, events: T) -> Self {
        Self {
            keeper,
            events: Arc::new(RwLock::new(events)),
            marker: std::marker::PhantomData,
        }
    }

    /// Folder identifier.
    pub fn id(&self) -> &VaultId {
        self.keeper.id()
    }

    /// Gatekeeper for this folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Mutable gatekeeper for this folder.
    pub fn keeper_mut(&mut self) -> &mut Gatekeeper {
        &mut self.keeper
    }

    /// Clone of the event log.
    pub fn event_log(&self) -> Arc<RwLock<T>> {
        Arc::clone(&self.events)
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
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        let event = self.keeper.create(secret_data).await?;
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        self.keeper.read(id).await
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        if let Some(event) =
            self.keeper.update(id, secret_meta, secret).await?
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
        if let Some(event) = self.keeper.delete(id).await? {
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
        Ok(self.set_meta(&meta).await?)
    }

    /// Set the folder meta data.
    pub async fn set_meta(&mut self, meta: &VaultMeta) -> Result<WriteEvent> {
        let event = self.keeper.set_vault_meta(&meta).await?;
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Folder commit state.
    pub async fn commit_state(&self) -> Result<CommitState> {
        let event_log = self.events.read().await;
        Ok(event_log.tree().commit_state()?)
    }

    /// Apply events to the event log.
    pub(super) async fn apply(
        &mut self,
        events: Vec<&WriteEvent>,
    ) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.apply(events).await?;
        Ok(())
    }

    /// Clear events from the event log.
    pub(super) async fn clear(&mut self) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.clear().await?;
        Ok(())
    }

    #[cfg(feature = "sync")]
    pub(crate) async fn replay_checked(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<CheckedPatch> {
        let checked_patch = {
            let mut event_log = self.events.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            for event in diff.patch.iter() {
                match event {
                    WriteEvent::CreateVault(_) => {
                        tracing::warn!("replay got create vault event");
                    }
                    WriteEvent::SetVaultName(name) => {
                        self.keeper.set_vault_name(name.to_owned()).await?;
                    }
                    WriteEvent::SetVaultMeta(aead) => {
                        let meta = self.keeper.decrypt_meta(aead).await?;
                        self.keeper.set_vault_meta(&meta).await?;
                    }
                    WriteEvent::CreateSecret(id, vault_commit) => {
                        let (meta, secret) = self
                            .keeper
                            .decrypt_secret(vault_commit, None)
                            .await?;
                        let row = SecretRow::new(*id, meta, secret);
                        self.keeper.create(&row).await?;
                    }
                    WriteEvent::UpdateSecret(id, vault_commit) => {
                        let (meta, secret) = self
                            .keeper
                            .decrypt_secret(vault_commit, None)
                            .await?;
                        self.keeper.update(id, meta, secret).await?;
                    }
                    WriteEvent::DeleteSecret(id) => {
                        self.keeper.delete(id).await?;
                    }
                    WriteEvent::Noop => {
                        tracing::error!("replay got noop event");
                    }
                }
            }
        }

        Ok(checked_patch)
    }
}

impl Folder<FolderEventLog, DiscLog, DiscLog, DiscData> {
    /// Create a new folder from a vault file on disc.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log = FolderEventLog::new(events_path).await?;
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

        Ok(Self::init(keeper, event_log))
    }

    /// Load an identity folder event log from the given paths.
    pub async fn new_event_log(
        paths: &Paths,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let mut event_log =
            FolderEventLog::new(paths.identity_events()).await?;
        event_log.load_tree().await?;
        Ok(Arc::new(RwLock::new(event_log)))
    }
}

impl Folder<MemoryFolderLog, MemoryLog, MemoryLog, MemoryData> {
    /// Create a new folder from a vault buffer
    /// that writes to memory.
    pub async fn new(buffer: impl AsRef<[u8]>) -> Result<Self> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        let keeper = Gatekeeper::new(vault);
        Ok(Self::init(keeper, MemoryFolderLog::new()))
    }
}
