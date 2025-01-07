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
    encode,
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{Summary, Vault, VaultAccess};
use std::{borrow::Cow, path::PathBuf};

/// Write changes to a vault in the database.
pub struct VaultDatabaseWriter {
    client: Client,
    folder_id: VaultId,
}

impl VaultDatabaseWriter {
    /// Create a new vault database writer.
    pub async fn new(client: Client, folder_id: VaultId) -> Self {
        Self { client, folder_id }
    }
}

#[async_trait]
impl VaultAccess for VaultDatabaseWriter {
    type Error = Error;

    async fn summary(&self) -> Result<Summary> {
        let folder_id = self.folder_id.clone();
        let row = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                let row = folder.find_one_optional(&folder_id)?;
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
        let folder_id = self.folder_id.clone();
        let folder_name = name.clone();
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_name(&folder_id, &folder_name)?;
                Ok(())
            })
            .await?;
        Ok(WriteEvent::SetVaultName(name))
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        let folder_id = self.folder_id.clone();
        let folder_flags = flags.bits().to_le_bytes();
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_flags(&folder_id, folder_flags.as_slice())?;
                Ok(())
            })
            .await?;
        Ok(WriteEvent::SetVaultFlags(flags))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent> {
        let folder_id = self.folder_id.clone();
        let folder_meta = encode(&meta_data).await?;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_meta(&folder_id, folder_meta.as_slice())?;
                Ok(())
            })
            .await?;
        Ok(WriteEvent::SetVaultMeta(meta_data))
    }

    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        self.insert_secret(SecretId::new_v4(), commit, secret).await
    }

    async fn insert_secret(
        &mut self,
        secret_id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        let folder_id = self.folder_id.clone();
        let VaultEntry(entry_meta, entry_secret) = &secret;
        let meta_blob = encode(entry_meta).await?;
        let secret_blob = encode(entry_secret).await?;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.insert_secret(
                    &folder_id,
                    &secret_id,
                    &commit,
                    meta_blob.as_slice(),
                    secret_blob.as_slice(),
                )?;
                Ok(())
            })
            .await?;
        Ok(WriteEvent::CreateSecret(
            secret_id,
            VaultCommit(commit, secret),
        ))
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
