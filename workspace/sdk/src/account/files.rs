//! File manager to keep external files in sync
//! as secrets are created, updated and moved.

use crate::{
    account::Account,
    commit::CommitState,
    events::{Event, FileEvent},
    storage::{
        files::{
            basename, list_folder_files, EncryptedFile, FileMutationEvent,
            FileProgress, FileStorage, FileStorageSync,
        },
        AccessOptions,
    },
    vault::{
        secret::{
            FileContent, Secret, SecretId, SecretMeta, SecretRow, UserData,
        },
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

    /// Update a file secret.
    ///
    /// If the secret exists and is not a file secret it will be
    /// converted to a file secret so take care to ensure you only
    /// use this on file secrets.
    pub async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(
            secret_id,
            meta,
            Some(secret),
            options,
            destination,
        )
        .await
    }
}
