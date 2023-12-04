//! File manager to keep external files in sync
//! as secrets are created, updated and moved.

use crate::{
    account::Account,
    events::FileEvent,
    storage::files::{
        basename, list_folder_files, EncryptedFile, FileMutationEvent,
        FileProgress, FileStorage, FileStorageSync,
    },
    vault::{
        secret::{FileContent, Secret, SecretId, SecretRow, UserData},
        Summary, VaultId,
    },
    vfs, Error, Result,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tokio::sync::mpsc;
use tracing::{span, Level};

impl<D> Account<D> {
    /// Decrypt a file and return the buffer.
    pub async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        reader.download_file(vault_id, secret_id, file_name).await
    }

    /// Append file mutation events to the file event log.
    pub(crate) async fn append_file_mutation_events(
        &mut self,
        events: &[FileMutationEvent],
    ) -> Result<()> {
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.append_file_mutation_events(events).await
    }

    /// Update external files when a file secret is updated.
    pub(crate) async fn update_files(
        &mut self,
        old_summary: &Summary,
        new_summary: &Summary,
        old_secret: &SecretRow,
        new_secret: SecretRow,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<Vec<FileMutationEvent>> {
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer
            .update_files(
                old_summary,
                new_summary,
                old_secret,
                new_secret,
                file_progress,
            )
            .await
    }

    /// Delete a collection of files from the external storage.
    pub(crate) async fn delete_files(
        &self,
        summary: &Summary,
        secret_data: &SecretRow,
        targets: Option<Vec<&Secret>>,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<Vec<FileMutationEvent>> {
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer
            .delete_files(summary, secret_data, targets, file_progress)
            .await
    }

    /// Delete a file from the storage location.
    pub(crate) async fn delete_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<FileEvent> {
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.delete_file(vault_id, secret_id, file_name).await
    }

    /// Move a collection of external storage files.
    pub(crate) async fn move_files(
        &self,
        secret_data: &SecretRow,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        targets: Option<Vec<&Secret>>,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<Vec<FileMutationEvent>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        reader
            .move_files(
                secret_data,
                old_vault_id,
                new_vault_id,
                old_secret_id,
                new_secret_id,
                targets,
                file_progress,
            )
            .await
    }

    /// Move the encrypted file for external file storage.
    pub(crate) async fn move_file(
        &self,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        file_name: &str,
    ) -> Result<FileMutationEvent> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        reader
            .move_file(
                old_vault_id,
                new_vault_id,
                old_secret_id,
                new_secret_id,
                file_name,
            )
            .await
    }
}
