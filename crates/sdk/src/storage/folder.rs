//! Storage backed by the filesystem.
use crate::{
    commit::{CommitHash, CommitState},
    constants::EVENT_LOG_EXT,
    crypto::AccessKey,
    decode,
    events::{
        DiscData, DiscLog, EventLogExt, FolderEventLog, FolderReducer,
        LogEvent, MemoryData, MemoryFolderLog, MemoryLog, ReadEvent,
        WriteEvent,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Gatekeeper, Vault, VaultId, VaultMeta, VaultWriter,
    },
    vfs, Error, Paths, Result,
};

use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[cfg(feature = "sync")]
use crate::sync::{
    CheckedPatch, FolderDiff, FolderMergeOptions, MergeSource,
};

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
        let event = self.keeper.create_secret(secret_data).await?;
        let mut events = self.events.write().await;
        events.apply(vec![&event]).await?;
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        self.keeper.read_secret(id).await
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
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
        event_log.tree().commit_state()
    }

    /// Folder root commit hash.
    pub async fn root_hash(&self) -> Result<CommitHash> {
        let event_log = self.events.read().await;
        event_log.tree().root().ok_or(Error::NoRootCommit)
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
    pub(crate) async fn merge(
        &mut self,
        source: MergeSource<WriteEvent>,
        mut options: FolderMergeOptions<'_>,
    ) -> Result<CheckedPatch> {
        match source {
            MergeSource::Checked(diff) => {
                let checked_patch = {
                    let mut event_log = self.events.write().await;
                    event_log.patch_checked(&diff.before, &diff.patch).await?
                };

                if let CheckedPatch::Success(_, _) = &checked_patch {
                    for record in diff.patch.iter() {
                        let event =
                            record.decode_event::<WriteEvent>().await?;
                        tracing::debug!(event_kind = %event.event_kind());
                        match &event {
                            WriteEvent::Noop => {
                                tracing::error!("merge got noop event");
                            }
                            WriteEvent::CreateVault(_) => {
                                tracing::warn!(
                                    "merge got create vault event"
                                );
                            }
                            WriteEvent::SetVaultName(name) => {
                                self.keeper
                                    .set_vault_name(name.to_owned())
                                    .await?;
                            }
                            WriteEvent::SetVaultMeta(aead) => {
                                let meta =
                                    self.keeper.decrypt_meta(aead).await?;
                                self.keeper.set_vault_meta(&meta).await?;
                            }
                            WriteEvent::CreateSecret(id, vault_commit) => {
                                let (meta, secret) = self
                                    .keeper
                                    .decrypt_secret(vault_commit, None)
                                    .await?;

                                let mut urn =
                                    if let FolderMergeOptions::Urn(_, _) =
                                        &options
                                    {
                                        meta.urn.clone()
                                    } else {
                                        None
                                    };

                                #[cfg(feature = "search")]
                                let mut index_doc =
                                    if let FolderMergeOptions::Search(
                                        folder_id,
                                        index,
                                    ) = &options
                                    {
                                        Some(index.prepare(
                                            folder_id, id, &meta, &secret,
                                        ))
                                    } else {
                                        None
                                    };

                                let row = SecretRow::new(*id, meta, secret);
                                self.keeper.create_secret(&row).await?;

                                // Add to the URN lookup index
                                if let (
                                    Some(urn),
                                    FolderMergeOptions::Urn(folder_id, index),
                                ) = (urn.take(), &mut options)
                                {
                                    index.insert((*folder_id, urn), *id);
                                }

                                #[cfg(feature = "search")]
                                if let (
                                    Some(index_doc),
                                    FolderMergeOptions::Search(_, index),
                                ) = (index_doc.take(), &mut options)
                                {
                                    index.commit(index_doc);
                                }
                            }
                            WriteEvent::UpdateSecret(id, vault_commit) => {
                                let (meta, secret) = self
                                    .keeper
                                    .decrypt_secret(vault_commit, None)
                                    .await?;

                                #[cfg(feature = "search")]
                                let mut index_doc =
                                    if let FolderMergeOptions::Search(
                                        folder_id,
                                        index,
                                    ) = &mut options
                                    {
                                        // Must remove from the index before we
                                        // prepare a new document otherwise the
                                        // document would be stale as `prepare()`
                                        // and `commit()` are for new documents
                                        index.remove(folder_id, id);

                                        Some(index.prepare(
                                            folder_id, id, &meta, &secret,
                                        ))
                                    } else {
                                        None
                                    };

                                self.keeper
                                    .update_secret(id, meta, secret)
                                    .await?;

                                #[cfg(feature = "search")]
                                if let (
                                    Some(index_doc),
                                    FolderMergeOptions::Search(_, index),
                                ) = (index_doc.take(), &mut options)
                                {
                                    index.commit(index_doc);
                                }
                            }
                            WriteEvent::DeleteSecret(id) => {
                                let mut urn =
                                    if let FolderMergeOptions::Urn(_, _) =
                                        &options
                                    {
                                        if let Some((meta, _, _)) = self
                                            .keeper
                                            .read_secret(id)
                                            .await?
                                        {
                                            meta.urn().cloned()
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                self.keeper.delete_secret(id).await?;

                                // Remove from the URN lookup index
                                if let (
                                    Some(urn),
                                    FolderMergeOptions::Urn(folder_id, index),
                                ) = (urn.take(), &mut options)
                                {
                                    index.remove(&(*folder_id, urn));
                                }

                                #[cfg(feature = "search")]
                                if let FolderMergeOptions::Search(
                                    folder_id,
                                    index,
                                ) = &mut options
                                {
                                    index.remove(folder_id, id);
                                }
                            }
                        }
                    }
                } else {
                    // FIXME: handle conflict situation
                    println!("todo! folder patch could not be merged");
                }

                Ok(checked_patch)
            }
            MergeSource::Forced(patch) => {
                let mut event_log = self.events.write().await;
                event_log.truncate().await?;
                let commits = event_log.patch_unchecked(&patch).await?;
                let head = event_log.tree().head()?;

                // Build a new vault
                let vault = FolderReducer::new()
                    .reduce(&*event_log)
                    .await?
                    .build(true)
                    .await?;
                self.keeper.replace_vault(vault, true).await?;

                Ok(CheckedPatch::Success(head, commits))
            }
        }
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
            let (_, events) = FolderReducer::split(vault.clone()).await?;
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
