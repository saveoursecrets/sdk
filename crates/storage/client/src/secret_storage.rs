//! Blanket implementation of secret storage trait.
use crate::traits::private::Internal;
use crate::{
    AccessOptions, ClientAccountStorage, ClientBaseStorage,
    ClientFolderStorage, ClientSecretStorage, Error, Result,
    StorageChangeEvent,
};
use async_trait::async_trait;
use sos_backend::StorageError;
use sos_core::{
    SecretId, VaultCommit, VaultId,
    events::{ReadEvent, WriteEvent},
};
use sos_vault::Summary;
use sos_vault::secret::{Secret, SecretMeta, SecretRow};

#[cfg(feature = "files")]
use sos_core::AuthenticationError;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T> ClientSecretStorage for T
where
    T: ClientAccountStorage
        + ClientFolderStorage
        + ClientBaseStorage
        + Send
        + Sync,
{
    async fn create_secret(
        &mut self,
        secret_data: SecretRow,
        #[cfg(not(feature = "files"))] options: AccessOptions,
        #[cfg(feature = "files")] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        self.guard_authenticated(Internal)?;

        let summary = if let Some(folder_id) = &options.folder {
            self.find(|f| f.id() == folder_id)
                .cloned()
                .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?
        } else {
            self.current_folder().ok_or(Error::NoOpenVault)?
        };

        #[cfg(feature = "search")]
        let index_doc = if let Some(index) = self.search_index() {
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
                .ok_or_else(|| AuthenticationError::NotAuthenticated)?
                .create_files(
                    &summary,
                    secret_data,
                    &mut options.file_progress,
                )
                .await?;

            if let Some((id, secret_data)) = write_update {
                // Update with new checksum(s)
                self.write_secret(
                    &summary,
                    &id,
                    secret_data,
                    false,
                    Internal,
                )
                .await?;
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
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .append_file_mutation_events(&result.file_events)
            .await?;

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) =
            (self.search_index(), index_doc)
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
        self.guard_authenticated(Internal)?;

        let folder = self
            .folders()
            .get(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?;
        Ok(folder.raw_secret(secret_id).await?)
    }

    async fn read_secret(
        &self,
        id: &SecretId,
        options: &AccessOptions,
    ) -> Result<(Summary, SecretMeta, Secret, ReadEvent)> {
        self.guard_authenticated(Internal)?;

        let summary = if let Some(folder_id) = &options.folder {
            self.find(|f| f.id() == folder_id)
                .cloned()
                .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?
        } else {
            self.current_folder().ok_or(Error::NoOpenVault)?
        };

        let folder = self
            .folders()
            .get(summary.id())
            .ok_or(StorageError::FolderNotFound(*summary.id()))?;
        let result = folder
            .read_secret(id)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        Ok((summary, result.0, result.1, result.2))
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<StorageChangeEvent> {
        self.guard_authenticated(Internal)?;

        let (folder, old_meta, old_secret, _) =
            self.read_secret(secret_id, &options).await?;
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
            .write_secret(
                &folder,
                secret_id,
                secret_data.clone(),
                true,
                Internal,
            )
            .await?;

        // Must update the files before moving so checksums are correct
        #[cfg(feature = "files")]
        let file_events = {
            // let folder = self.current_folder().ok_or(Error::NoOpenVault)?;
            let (file_events, write_update) = self
                .external_file_manager_mut()
                .ok_or_else(|| AuthenticationError::NotAuthenticated)?
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
                self.write_secret(&folder, &id, secret_data, false, Internal)
                    .await?;
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
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn write_secret(
        &mut self,
        folder: &Summary,
        id: &SecretId,
        mut secret_data: SecretRow,
        #[cfg(not(feature = "search"))] _is_update: bool,
        #[cfg(feature = "search")] is_update: bool,
        _: Internal,
    ) -> Result<WriteEvent> {
        // let summary = self.current_folder().ok_or(Error::NoOpenVault)?;

        secret_data.meta_mut().touch();

        #[cfg(feature = "search")]
        let index_doc = if let Some(index) = self.search_index() {
            let search = index.search();
            let mut index = search.write().await;

            if is_update {
                // Must remove from the index before we
                // prepare a new document otherwise the
                // document would be stale as `prepare()`
                // and `commit()` are for new documents
                index.remove(folder.id(), id);
            }

            Some(index.prepare(
                folder.id(),
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
                .get_mut(folder.id())
                .ok_or(StorageError::FolderNotFound(*folder.id()))?;
            let (_, meta, secret) = secret_data.into();
            folder
                .update_secret(id, meta, secret)
                .await?
                .ok_or(Error::SecretNotFound(*id))?
        };

        #[cfg(feature = "search")]
        if let (Some(index), Some(index_doc)) =
            (self.search_index(), index_doc)
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
        self.guard_authenticated(Internal)?;

        #[cfg(feature = "files")]
        let (folder, secret_data) = {
            let (folder, meta, secret, _) =
                self.read_secret(secret_id, &options).await?;
            (folder, SecretRow::new(*secret_id, meta, secret))
        };

        let event = self.remove_secret(secret_id, &options).await?;

        let result = StorageChangeEvent {
            event,
            // Must update the files before moving so
            // checksums are correct
            #[cfg(feature = "files")]
            file_events: {
                self.external_file_manager_mut()
                    .ok_or_else(|| AuthenticationError::NotAuthenticated)?
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
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .append_file_mutation_events(&result.file_events)
            .await?;

        Ok(result)
    }

    async fn remove_secret(
        &mut self,
        id: &SecretId,
        options: &AccessOptions,
    ) -> Result<WriteEvent> {
        self.guard_authenticated(Internal)?;

        let summary = if let Some(folder_id) = &options.folder {
            self.find(|f| f.id() == folder_id)
                .cloned()
                .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?
        } else {
            self.current_folder().ok_or(Error::NoOpenVault)?
        };

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
        if let Some(index) = self.search_index() {
            let search = index.search();
            let mut writer = search.write().await;
            writer.remove(summary.id(), id);
        }

        Ok(event)
    }
}
