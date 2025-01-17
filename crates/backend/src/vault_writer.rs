use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    commit::CommitHash,
    crypto::AeadPack,
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_database::{async_sqlite::Client, VaultDatabaseWriter};
use sos_filesystem::VaultFileWriter;
use sos_vault::{EncryptedEntry, Summary, Vault};
use std::{borrow::Cow, path::Path};

/// Backend vault writer.
pub enum VaultWriter {
    /// Vault backed by a database table.
    Database(VaultDatabaseWriter<Error>),
    /// Vault backed by a file on disc.
    FileSystem(VaultFileWriter<Error>),
}

impl VaultWriter {
    /// Create a new database vault writer.
    pub fn new_db(client: Client, folder_id: VaultId) -> Self {
        Self::Database(VaultDatabaseWriter::<Error>::new(client, folder_id))
    }

    /// Create a new file system vault writer.
    pub fn new_fs<P: AsRef<Path>>(path: P) -> Self {
        Self::FileSystem(VaultFileWriter::<Error>::new(path))
    }
}

#[async_trait]
impl EncryptedEntry for VaultWriter {
    type Error = Error;

    async fn summary(&self) -> Result<Summary> {
        Ok(match self {
            Self::Database(inner) => inner.summary().await?,
            Self::FileSystem(inner) => inner.summary().await?,
        })
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>> {
        Ok(match self {
            Self::Database(inner) => inner.vault_name().await?,
            Self::FileSystem(inner) => inner.vault_name().await?,
        })
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        Ok(match self {
            Self::Database(inner) => inner.set_vault_name(name).await?,
            Self::FileSystem(inner) => inner.set_vault_name(name).await?,
        })
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        Ok(match self {
            Self::Database(inner) => inner.set_vault_flags(flags).await?,
            Self::FileSystem(inner) => inner.set_vault_flags(flags).await?,
        })
    }

    async fn set_vault_meta(&mut self, meta: AeadPack) -> Result<WriteEvent> {
        Ok(match self {
            Self::Database(inner) => inner.set_vault_meta(meta).await?,
            Self::FileSystem(inner) => inner.set_vault_meta(meta).await?,
        })
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
        Ok(match self {
            Self::Database(inner) => {
                inner.insert_secret(secret_id, commit, secret).await?
            }
            Self::FileSystem(inner) => {
                inner.insert_secret(secret_id, commit, secret).await?
            }
        })
    }

    async fn read_secret<'a>(
        &'a self,
        secret_id: &SecretId,
    ) -> Result<Option<(Cow<'a, VaultCommit>, ReadEvent)>> {
        Ok(match self {
            Self::Database(inner) => inner.read_secret(secret_id).await?,
            Self::FileSystem(inner) => inner.read_secret(secret_id).await?,
        })
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>> {
        Ok(match self {
            Self::Database(inner) => {
                inner.update_secret(secret_id, commit, secret).await?
            }
            Self::FileSystem(inner) => {
                inner.update_secret(secret_id, commit, secret).await?
            }
        })
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        Ok(match self {
            Self::Database(inner) => inner.delete_secret(secret_id).await?,
            Self::FileSystem(inner) => inner.delete_secret(secret_id).await?,
        })
    }

    async fn replace_vault(&mut self, vault: &Vault) -> Result<()> {
        Ok(match self {
            Self::Database(inner) => inner.replace_vault(vault).await?,
            Self::FileSystem(inner) => inner.replace_vault(vault).await?,
        })
    }
}
