//! Implements merging for folders.

// Ideally we want this code to be in the `sos-net`
// crate but we also need to share some traits with the
// server so we have to implement here otherwise we
// hit the problem with foreign trait implementations.

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

use crate::{
    sdk::{
        events::{
            CheckedPatch, EventLogExt, FolderDiff, FolderReducer, LogEvent,
            WriteEvent,
        },
        identity::IdentityFolder,
        storage::Folder,
        vault::secret::SecretRow,
        Result,
    },
    FolderMergeOptions,
};

/// Merge operations for the identity folder.
#[async_trait]
pub(crate) trait IdentityFolderMerge {
    /// Checked merge.
    async fn merge(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)>;

    /// Unchecked merge.
    async fn force_merge(&mut self, diff: &FolderDiff) -> Result<()>;
}

/// Merge operations for folders.
#[async_trait]
pub(crate) trait FolderMerge {
    /// Checked merge.
    async fn merge<'a>(
        &mut self,
        diff: &FolderDiff,
        options: FolderMergeOptions<'a>,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)>;

    /// Unchecked merge.
    async fn force_merge(&mut self, diff: &FolderDiff) -> Result<()>;
}

#[async_trait]
impl<T, R, W, D> IdentityFolderMerge for IdentityFolder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    W: AsyncWrite + AsyncSeek + Unpin + Send + Sync,
    D: Clone + Send + Sync,
{
    async fn merge(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let id = *self.folder_id();
        let index = &mut self.index;

        self.folder
            .merge(diff, FolderMergeOptions::Urn(id, index))
            .await
    }

    async fn force_merge(&mut self, diff: &FolderDiff) -> Result<()> {
        self.folder.force_merge(diff).await
    }
}

#[async_trait]
impl<T, R, W, D> FolderMerge for Folder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    W: AsyncWrite + AsyncSeek + Unpin + Send + Sync,
    D: Clone + Send + Sync,
{
    async fn merge<'a>(
        &mut self,
        diff: &FolderDiff,
        mut options: FolderMergeOptions<'a>,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let mut events = Vec::new();
        let checked_patch = {
            let event_log = self.event_log();
            let mut event_log = event_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            for record in diff.patch.iter() {
                let event = record.decode_event::<WriteEvent>().await?;
                tracing::debug!(event_kind = %event.event_kind());
                match &event {
                    WriteEvent::Noop => unreachable!(),
                    WriteEvent::CreateVault(_) => {
                        tracing::warn!("merge got create vault event");
                    }
                    WriteEvent::SetVaultName(name) => {
                        self.keeper_mut()
                            .set_vault_name(name.to_owned())
                            .await?;
                    }
                    WriteEvent::SetVaultFlags(flags) => {
                        self.keeper_mut()
                            .set_vault_flags(flags.clone())
                            .await?;
                    }
                    WriteEvent::SetVaultMeta(aead) => {
                        let meta =
                            self.keeper_mut().decrypt_meta(aead).await?;
                        self.keeper_mut().set_vault_meta(&meta).await?;
                    }
                    WriteEvent::CreateSecret(id, vault_commit) => {
                        let (meta, secret) = self
                            .keeper_mut()
                            .decrypt_secret(vault_commit, None)
                            .await?;

                        #[allow(irrefutable_let_patterns)]
                        let mut urn =
                            if let FolderMergeOptions::Urn(_, _) = &options {
                                meta.urn().cloned()
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
                                Some(
                                    index.prepare(
                                        folder_id, id, &meta, &secret,
                                    ),
                                )
                            } else {
                                None
                            };

                        let row = SecretRow::new(*id, meta, secret);
                        self.keeper_mut().create_secret(&row).await?;

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
                            .keeper_mut()
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

                                Some(
                                    index.prepare(
                                        folder_id, id, &meta, &secret,
                                    ),
                                )
                            } else {
                                None
                            };

                        self.keeper_mut()
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
                        #[allow(irrefutable_let_patterns)]
                        let mut urn =
                            if let FolderMergeOptions::Urn(_, _) = &options {
                                if let Some((meta, _, _)) =
                                    self.keeper().read_secret(id).await?
                                {
                                    meta.urn().cloned()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        self.keeper_mut().delete_secret(id).await?;

                        // Remove from the URN lookup index
                        if let (
                            Some(urn),
                            FolderMergeOptions::Urn(folder_id, index),
                        ) = (urn.take(), &mut options)
                        {
                            index.remove(&(*folder_id, urn));
                        }

                        #[cfg(feature = "search")]
                        if let FolderMergeOptions::Search(folder_id, index) =
                            &mut options
                        {
                            index.remove(folder_id, id);
                        }
                    }
                }

                events.push(event);
            }
        }

        Ok((checked_patch, events))
    }

    async fn force_merge(&mut self, diff: &FolderDiff) -> Result<()> {
        let event_log = self.event_log();
        let mut event_log = event_log.write().await;
        event_log.patch_replace(diff).await?;

        // Build a new vault
        let vault = FolderReducer::new()
            .reduce(&*event_log)
            .await?
            .build(true)
            .await?;
        self.keeper_mut().replace_vault(vault, true).await?;

        Ok(())
    }
}
