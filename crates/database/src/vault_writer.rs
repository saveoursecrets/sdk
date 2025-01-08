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
    decode, encode,
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{Summary, Vault, VaultAccess};
use std::borrow::Cow;

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
                let row = folder.find_optional(&folder_id)?;
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
        secret_id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        let folder_id = self.folder_id.clone();
        let folder_secret_id = *secret_id;
        let secret_row = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.find_secret(&folder_id, &folder_secret_id)?)
            })
            .await?;

        let event = ReadEvent::ReadSecret(*secret_id);
        if let Some(row) = secret_row {
            let commit_hash = CommitHash(row.commit.as_slice().try_into()?);
            let meta: AeadPack = decode(&row.meta).await?;
            let secret: AeadPack = decode(&row.secret).await?;
            let entry = VaultEntry(meta, secret);
            let commit = VaultCommit(commit_hash, entry);
            Ok((Some(Cow::Owned(commit)), event))
        } else {
            Ok((None, event))
        }
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>> {
        let folder_id = self.folder_id.clone();
        let folder_secret_id = *secret_id;
        let VaultEntry(entry_meta, entry_secret) = &secret;
        let meta_blob = encode(entry_meta).await?;
        let secret_blob = encode(entry_secret).await?;
        let updated = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.update_secret(
                    &folder_id,
                    &folder_secret_id,
                    &commit,
                    meta_blob.as_slice(),
                    secret_blob.as_slice(),
                )?)
            })
            .await?;
        Ok(updated.then_some(WriteEvent::UpdateSecret(
            *secret_id,
            VaultCommit(commit, secret),
        )))
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        let folder_id = self.folder_id.clone();
        let folder_secret_id = *secret_id;
        let deleted = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.delete_secret(&folder_id, &folder_secret_id)?)
            })
            .await?;
        Ok(deleted.then_some(WriteEvent::DeleteSecret(*secret_id)))
    }

    async fn replace_vault(&mut self, vault: &Vault) -> Result<()> {
        let folder_id = self.folder_id.clone();

        let mut insert_secrets = Vec::new();
        for (secret_id, secret) in vault.iter() {
            let VaultCommit(commit, VaultEntry(entry_meta, entry_secret)) =
                &secret;
            let meta_blob = encode(entry_meta).await?;
            let secret_blob = encode(entry_secret).await?;

            insert_secrets.push((
                *secret_id,
                *commit,
                meta_blob,
                secret_blob,
            ));
        }

        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let folder = FolderEntity::new(&tx);
                let folder_row = folder.find_one(&folder_id)?;
                folder.delete_all_secrets(&folder_id)?;
                for (secret_id, commit, meta, secret) in insert_secrets {
                    folder.insert_secret_by_row_id(
                        folder_row.row_id,
                        &secret_id,
                        &commit,
                        meta.as_slice(),
                        secret.as_slice(),
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}
