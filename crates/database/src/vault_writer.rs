//! Write vault changes to a database.
use crate::{
    db::{FolderEntity, FolderRecord, SecretRecord, SecretRow},
    Error,
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
use sos_vault::{EncryptedEntry, Summary, Vault};
use std::borrow::Cow;

/// Write changes to a vault in the database.
pub struct VaultDatabaseWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_vault::Error>
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    client: Client,
    folder_id: VaultId,
    marker: std::marker::PhantomData<E>,
}

impl<E> VaultDatabaseWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_vault::Error>
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new vault database writer.
    pub fn new(client: Client, folder_id: VaultId) -> Self {
        Self {
            client,
            folder_id,
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<E> EncryptedEntry for VaultDatabaseWriter<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_vault::Error>
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn summary(&self) -> Result<Summary, Self::Error> {
        let folder_id = self.folder_id.clone();
        let row = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                let row = folder.find_optional(&folder_id)?;
                Ok(row)
            })
            .await
            .map_err(Error::from)?;
        let row = row.ok_or(Error::DatabaseFolderNotFound(folder_id))?;
        let record = FolderRecord::from_row(row).await?;
        Ok(record.summary)
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>, Self::Error> {
        let summary = self.summary().await?;
        Ok(Cow::Owned(summary.name().to_string()))
    }

    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent, Self::Error> {
        let folder_id = self.folder_id.clone();
        let folder_name = name.clone();
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_name(&folder_id, &folder_name)?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(WriteEvent::SetVaultName(name))
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent, Self::Error> {
        let folder_id = self.folder_id.clone();
        let folder_flags = flags.bits().to_le_bytes();
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_flags(&folder_id, folder_flags.as_slice())?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(WriteEvent::SetVaultFlags(flags))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent, Self::Error> {
        let folder_id = self.folder_id.clone();
        let folder_meta = encode(&meta_data).await?;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.update_meta(&folder_id, folder_meta.as_slice())?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(WriteEvent::SetVaultMeta(meta_data))
    }

    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent, Self::Error> {
        self.insert_secret(SecretId::new_v4(), commit, secret).await
    }

    async fn insert_secret(
        &mut self,
        secret_id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent, Self::Error> {
        let folder_id = self.folder_id.clone();
        let secret_row = SecretRow::new(&secret_id, &commit, &secret).await?;
        self.client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                folder.insert_secret(&folder_id, &secret_row)?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(WriteEvent::CreateSecret(
            secret_id,
            VaultCommit(commit, secret),
        ))
    }

    async fn read_secret<'a>(
        &'a self,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'a, VaultCommit>, ReadEvent)>, Self::Error> {
        let folder_id = self.folder_id.clone();
        let folder_secret_id = *secret_id;
        let secret_row = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.find_secret(&folder_id, &folder_secret_id)?)
            })
            .await
            .map_err(Error::from)?;

        let event = ReadEvent::ReadSecret(*secret_id);
        if let Some(row) = secret_row {
            let record = SecretRecord::from_row(row).await?;
            Ok(Some((Cow::Owned(record.commit), event)))
        } else {
            Ok(None)
        }
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>, Self::Error> {
        let folder_id = self.folder_id.clone();
        let secret_row = SecretRow::new(secret_id, &commit, &secret).await?;
        let updated = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.update_secret(&folder_id, &secret_row)?)
            })
            .await
            .map_err(Error::from)?;
        Ok(updated.then_some(WriteEvent::UpdateSecret(
            *secret_id,
            VaultCommit(commit, secret),
        )))
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<Option<WriteEvent>, Self::Error> {
        let folder_id = self.folder_id.clone();
        let folder_secret_id = *secret_id;
        let deleted = self
            .client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.delete_secret(&folder_id, &folder_secret_id)?)
            })
            .await
            .map_err(Error::from)?;
        Ok(deleted.then_some(WriteEvent::DeleteSecret(*secret_id)))
    }

    async fn replace_vault(
        &mut self,
        vault: &Vault,
    ) -> Result<(), Self::Error> {
        let folder_id = self.folder_id.clone();
        let mut insert_secrets = Vec::new();
        for (secret_id, commit) in vault.iter() {
            let VaultCommit(commit, entry) = commit;
            insert_secrets
                .push(SecretRow::new(secret_id, commit, entry).await?);
        }

        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let folder = FolderEntity::new(&tx);
                let folder_row = folder.find_one(&folder_id)?;
                folder.delete_all_secrets(&folder_id)?;
                for secret_row in insert_secrets {
                    folder.insert_secret_by_row_id(
                        folder_row.row_id,
                        &secret_row,
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(())
    }
}
