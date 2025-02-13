//! Blanket implementation of secret storage trait.
use crate::{
    AccessOptions, ClientAccountStorage, ClientFolderStorage,
    ClientSecretStorage, Error, Result, StorageChangeEvent,
};
use async_trait::async_trait;
use sos_backend::StorageError;
use sos_core::events::{ReadEvent, WriteEvent};
use sos_core::{SecretId, VaultId};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    VaultCommit,
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T> ClientSecretStorage for T
where
    T: ClientAccountStorage + ClientFolderStorage,
{
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        #[cfg(feature = "search")]
        let index_doc = if let Some(index) = self.index().ok() {
            let search = index.search();
            let index = search.read().await;
            Some(index.prepare(
                summary.id(),
                secret_data.id(),
                secret_data.meta(),
                secret_data.secret(),
            ))
        } else {
            None
        };

        let event = {
            let folder = self
                .folders_mut()
                .get_mut(summary.id())
                .ok_or(StorageError::FolderNotFound(*summary.id()))?;
            folder.create_secret(&secret_data).await?
        };

        #[cfg(feature = "files")]
        let file_events = {
            let (file_events, write_update) = self
                .external_file_manager_mut()
                .create_files(
                    &summary,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;

            if let Some((id, secret_data)) = write_update {
                // Update with new checksum(s)
                self.write_secret(&id, secret_data, false).await?;
            }

            file_events
        };

        let result = StorageChangeEvent {
            event,
            #[cfg(feature = "files")]
            file_events,
        };

        #[cfg(feature = "files")]
        self.external_file_manager_mut()
            .append_file_mutation_events(&result.file_events)
            .await?;

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) = (self.index().ok(), index_doc)
        {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(result)
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(VaultCommit, ReadEvent)>> {
        let folder = self
            .folders()
            .get(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;
        Ok(folder.raw_secret(secret_id).await?)
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;
        let folder = self
            .folders()
            .get(summary.id())
            .ok_or(StorageError::FolderNotFound(*summary.id()))?;
        let result = folder
            .read_secret(id)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        let (old_meta, old_secret, _) = self.read_secret(secret_id).await?;
        let old_secret_data =
            SecretRow::new(*secret_id, old_meta, old_secret);

        let secret_data = if let Some(secret) = secret {
            SecretRow::new(*secret_id, meta, secret)
        } else {
            let mut secret_data = old_secret_data.clone();
            *secret_data.meta_mut() = meta;
            secret_data
        };

        let event = self
            .write_secret(secret_id, secret_data.clone(), true)
            .await?;

        // Must update the files before moving so checksums are correct
        #[cfg(feature = "files")]
        let file_events = {
            let folder = self.current_folder().ok_or(Error::NoOpenVault)?;
            let (file_events, write_update) = self
                .external_file_manager_mut()
                .update_files(
                    &folder,
                    &folder,
                    &old_secret_data,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;

            if let Some((id, secret_data)) = write_update {
                // Update with new checksum(s)
                self.write_secret(&id, secret_data, false).await?;
            }

            file_events
        };

        let result = StorageChangeEvent {
            event,
            #[cfg(feature = "files")]
            file_events,
        };

        #[cfg(feature = "files")]
        self.external_file_manager_mut()
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn write_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[allow(unused_variables)] is_update: bool,
    ) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        secret_data.meta_mut().touch();

        #[cfg(feature = "search")]
        let index_doc = if let Some(index) = self.index().ok() {
            let search = index.search();
            let mut index = search.write().await;

            if is_update {
                // Must remove from the index before we
                // prepare a new document otherwise the
                // document would be stale as `prepare()`
                // and `commit()` are for new documents
                index.remove(summary.id(), id);
            }

            Some(index.prepare(
                summary.id(),
                id,
                secret_data.meta(),
                secret_data.secret(),
            ))
        } else {
            None
        };

        let event = {
            let folder = self
                .folders_mut()
                .get_mut(summary.id())
                .ok_or(StorageError::FolderNotFound(*summary.id()))?;
            let (_, meta, secret) = secret_data.into();
            folder
                .update_secret(id, meta, secret)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) = (self.index().ok(), index_doc)
        {
            let search = index.search();
            let mut index = search.write().await;
            index.commit(index_doc)
        }

        Ok(event)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        #[cfg(feature = "files")]
        let secret_data = {
            let (meta, secret, _) = self.read_secret(secret_id).await?;
            SecretRow::new(*secret_id, meta, secret)
        };

        let event = self.remove_secret(secret_id).await?;

        let result = StorageChangeEvent {
            event,
            // Must update the files before moving so checksums are correct
            #[cfg(feature = "files")]
            file_events: {
                let folder =
                    self.current_folder().ok_or(Error::NoOpenVault)?;
                self.external_file_manager_mut()
                    .delete_files(
                        &folder,
                        &secret_data,
                        None,
                        &mut options.file_progress,
                    )
                    .await?
            },
        };

        #[cfg(feature = "files")]
        self.external_file_manager_mut()
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn remove_secret(&mut self, id: &SecretId) -> Result<WriteEvent> {
        let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        let event = {
            let folder = self
                .folders_mut()
                .get_mut(summary.id())
                .ok_or(StorageError::FolderNotFound(*summary.id()))?;
            folder
                .delete_secret(id)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };

        #[cfg(feature = "search")]
        if let Some(index) = self.index().ok() {
            let search = index.search();
            let mut writer = search.write().await;
            writer.remove(summary.id(), id);
        }

        Ok(event)
    }
}
