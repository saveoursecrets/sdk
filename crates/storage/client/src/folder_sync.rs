//! Implements merging for folders.
use crate::Result;
use async_trait::async_trait;
use sos_backend::Folder;
use sos_core::{
    events::{
        patch::{CheckedPatch, FolderDiff},
        EventLog, LogEvent, WriteEvent,
    },
    VaultId,
};
use sos_login::IdentityFolder;
use sos_reducers::FolderReducer;
use sos_vault::{secret::SecretRow, SecretAccess};

/// Options for folder merge.
pub(crate) enum FolderMergeOptions<'a> {
    /// Update a URN lookup when merging.
    Urn(VaultId, &'a mut sos_login::UrnLookup),
    /// Update a search index when merging.
    #[cfg(feature = "search")]
    Search(VaultId, &'a mut sos_search::SearchIndex),
}

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
impl IdentityFolderMerge for IdentityFolder {
    async fn merge(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let id = self.folder_id().await;
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
impl FolderMerge for Folder {
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
            let access_point = self.access_point();
            let mut access_point = access_point.lock().await;

            for record in diff.patch.iter() {
                let event = record.decode_event::<WriteEvent>().await?;
                tracing::debug!(event_kind = %event.event_kind());
                match &event {
                    WriteEvent::Noop => unreachable!(),
                    WriteEvent::CreateVault(_) => {
                        tracing::warn!("merge got create vault event");
                    }
                    WriteEvent::SetVaultName(name) => {
                        access_point.set_vault_name(name.to_owned()).await?;
                    }
                    WriteEvent::SetVaultFlags(flags) => {
                        access_point.set_vault_flags(flags.clone()).await?;
                    }
                    WriteEvent::SetVaultMeta(aead) => {
                        let meta = access_point.decrypt_meta(aead).await?;
                        access_point.set_vault_meta(&meta).await?;
                    }
                    WriteEvent::CreateSecret(id, vault_commit) => {
                        let (meta, secret) = access_point
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
                        access_point.create_secret(&row).await?;

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
                        let (meta, secret) = access_point
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

                        access_point.update_secret(id, meta, secret).await?;

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
                                    access_point.read_secret(id).await?
                                {
                                    meta.urn().cloned()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        access_point.delete_secret(id).await?;

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
        event_log.replace_all_events(diff).await?;

        // Build a new vault
        let vault = FolderReducer::new()
            .reduce(&*event_log)
            .await?
            .build(true)
            .await?;

        let access_point = self.access_point();
        let mut access_point = access_point.lock().await;
        access_point.replace_vault(vault, true).await?;

        Ok(())
    }
}
