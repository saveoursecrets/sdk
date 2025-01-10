use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    crypto::{AccessKey, AeadPack, PrivateKey},
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultFlags, VaultId,
};
use sos_database::{async_sqlite::Client, VaultDatabaseWriter};
use sos_filesystem::VaultFileWriter;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    AccessPoint, SecretAccess, Summary, Vault, VaultMeta,
};
use std::borrow::Cow;
use std::path::Path;

/// Backend access point implementation.
pub enum BackendAccessPoint {
    /// Database access point.
    Database(AccessPoint<Error>),
    /// File system access point.
    FileSystem(AccessPoint<Error>),
}

impl BackendAccessPoint {
    /// In-memory access point from a vault.
    pub fn new_vault(vault: Vault) -> Self {
        Self::FileSystem(AccessPoint::<Error>::new(vault))
    }

    /// Access point that mirrors to disc.
    pub async fn new_fs<P: AsRef<Path>>(
        vault: Vault,
        path: P,
    ) -> Result<Self> {
        let mirror = VaultFileWriter::<Error>::new(path).await?;
        Ok(Self::FileSystem(AccessPoint::<Error>::new_mirror(
            vault,
            Box::new(mirror),
        )))
    }

    /// Access point that mirrors to a database table.
    pub async fn new_db(
        vault: Vault,
        client: Client,
        folder_id: VaultId,
    ) -> Self {
        let mirror =
            VaultDatabaseWriter::<Error>::new(client, folder_id).await;
        Self::FileSystem(AccessPoint::<Error>::new_mirror(
            vault,
            Box::new(mirror),
        ))
    }
}

#[async_trait]
impl SecretAccess for BackendAccessPoint {
    type Error = Error;

    fn is_mirror(&self) -> bool {
        match self {
            BackendAccessPoint::Database(inner) => inner.is_mirror(),
            BackendAccessPoint::FileSystem(inner) => inner.is_mirror(),
        }
    }

    fn vault(&self) -> &Vault {
        match self {
            BackendAccessPoint::Database(inner) => inner.vault(),
            BackendAccessPoint::FileSystem(inner) => inner.vault(),
        }
    }

    fn vault_mut(&mut self) -> &mut Vault {
        match self {
            BackendAccessPoint::Database(inner) => inner.vault_mut(),
            BackendAccessPoint::FileSystem(inner) => inner.vault_mut(),
        }
    }

    async fn replace_vault(
        &mut self,
        vault: Vault,
        mirror_changes: bool,
    ) -> Result<()> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.replace_vault(vault, mirror_changes).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.replace_vault(vault, mirror_changes).await?
            }
        })
    }

    async fn reload_vault<P: AsRef<Path> + Send>(
        &mut self,
        path: P,
    ) -> Result<()> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.reload_vault(path).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.reload_vault(path).await?
            }
        })
    }

    fn set_vault(&mut self, vault: Vault) {
        match self {
            BackendAccessPoint::Database(inner) => inner.set_vault(vault),
            BackendAccessPoint::FileSystem(inner) => inner.set_vault(vault),
        }
    }

    fn summary(&self) -> &Summary {
        match self {
            BackendAccessPoint::Database(inner) => inner.summary(),
            BackendAccessPoint::FileSystem(inner) => inner.summary(),
        }
    }

    fn id(&self) -> &VaultId {
        match self {
            BackendAccessPoint::Database(inner) => inner.id(),
            BackendAccessPoint::FileSystem(inner) => inner.id(),
        }
    }

    fn name(&self) -> &str {
        match self {
            BackendAccessPoint::Database(inner) => inner.name(),
            BackendAccessPoint::FileSystem(inner) => inner.name(),
        }
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.set_vault_name(name).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.set_vault_name(name).await?
            }
        })
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.set_vault_flags(flags).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.set_vault_flags(flags).await?
            }
        })
    }

    async fn vault_meta(&self) -> Result<VaultMeta> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => inner.vault_meta().await?,
            BackendAccessPoint::FileSystem(inner) => {
                inner.vault_meta().await?
            }
        })
    }

    /// Set the meta data for the vault.
    async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.set_vault_meta(meta_data).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.set_vault_meta(meta_data).await?
            }
        })
    }

    async fn decrypt_meta(&self, meta_aead: &AeadPack) -> Result<VaultMeta> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.decrypt_meta(meta_aead).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.decrypt_meta(meta_aead).await?
            }
        })
    }

    async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret)> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.decrypt_secret(vault_commit, private_key).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.decrypt_secret(vault_commit, private_key).await?
            }
        })
    }

    async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.create_secret(secret_data).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.create_secret(secret_data).await?
            }
        })
    }

    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.raw_secret(id).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.raw_secret(id).await?
            }
        })
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.read_secret(id).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.read_secret(id).await?
            }
        })
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.update_secret(id, meta, secret).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.update_secret(id, meta, secret).await?
            }
        })
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => {
                inner.delete_secret(id).await?
            }
            BackendAccessPoint::FileSystem(inner) => {
                inner.delete_secret(id).await?
            }
        })
    }

    async fn verify(&self, key: &AccessKey) -> Result<()> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => inner.verify(key).await?,
            BackendAccessPoint::FileSystem(inner) => {
                inner.verify(key).await?
            }
        })
    }

    async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        Ok(match self {
            BackendAccessPoint::Database(inner) => inner.unlock(key).await?,
            BackendAccessPoint::FileSystem(inner) => {
                inner.unlock(key).await?
            }
        })
    }

    fn lock(&mut self) {
        match self {
            BackendAccessPoint::Database(inner) => inner.lock(),
            BackendAccessPoint::FileSystem(inner) => inner.lock(),
        }
    }
}

impl From<BackendAccessPoint> for Vault {
    fn from(value: BackendAccessPoint) -> Self {
        match value {
            BackendAccessPoint::Database(inner) => inner.into(),
            BackendAccessPoint::FileSystem(inner) => inner.into(),
        }
    }
}
