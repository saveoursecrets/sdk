//! Implements random access to a single vault file in the database.
use crate::{
    db::{FolderEntity, FolderRecord},
    Error, Result,
};
use async_sqlite::Client;
use async_trait::async_trait;
use sos_core::{
    commit::CommitHash,
    crypto::AeadPack,
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{Summary, Vault, VaultAccess};
use std::{borrow::Cow, path::PathBuf};
use tokio::sync::Mutex;

/// Write changes to a vault in the database.
pub struct VaultDatabaseWriter {
    client: Mutex<Client>,
    folder_id: VaultId,
}

impl VaultDatabaseWriter {
    /// Create a new vault database writer.
    pub async fn new(client: Mutex<Client>, folder_id: VaultId) -> Self {
        Self { client, folder_id }
    }
}

#[async_trait]
impl VaultAccess for VaultDatabaseWriter {
    type Error = Error;

    async fn summary(&self) -> Result<Summary> {
        let client = self.client.lock().await;
        let folder_id = self.folder_id.clone();
        let row = client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let folder = FolderEntity::new(&tx);
                let row = folder.find_one(&folder_id)?;
                Ok(row)
            })
            .await?;
        let row = row.ok_or(Error::DatabaseFolderNotFound(folder_id))?;
        let record: FolderRecord = row.try_into()?;
        Ok(record.summary)
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>> {
        let summary = self.summary().await?;
        Ok(Cow::Owned(summary.name().to_string()))
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        todo!();
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn insert_secret(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn read_secret<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        todo!();
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    async fn replace_vault(&mut self, vault: &Vault) -> Result<()> {
        todo!();
    }

    async fn reload_vault(&mut self, path: PathBuf) -> Result<()> {
        todo!();
    }
}
