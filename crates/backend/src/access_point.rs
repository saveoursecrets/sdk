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
    ) -> Result<Self> {
        let mirror =
            VaultDatabaseWriter::<Error>::new(client, folder_id).await;
        Ok(Self::FileSystem(AccessPoint::<Error>::new_mirror(
            vault,
            Box::new(mirror),
        )))
    }
}

#[async_trait]
impl SecretAccess for BackendAccessPoint {
    type Error = Error;

    fn is_mirror(&self) -> bool {
        todo!();
    }

    fn vault(&self) -> &Vault {
        todo!();
    }

    fn vault_mut(&mut self) -> &mut Vault {
        todo!();
    }

    async fn replace_vault(
        &mut self,
        vault: Vault,
        mirror_changes: bool,
    ) -> Result<()> {
        todo!();
    }

    async fn reload_vault<P: AsRef<Path> + Send>(
        &mut self,
        path: P,
    ) -> Result<()> {
        todo!();
    }

    fn set_vault(&mut self, vault: Vault) {
        todo!();
    }

    fn summary(&self) -> &Summary {
        todo!();
    }

    fn id(&self) -> &VaultId {
        todo!();
    }

    fn name(&self) -> &str {
        todo!();
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

    async fn vault_meta(&self) -> Result<VaultMeta> {
        todo!();
    }

    /// Set the meta data for the vault.
    async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn decrypt_meta(&self, meta_aead: &AeadPack) -> Result<VaultMeta> {
        todo!();
    }

    async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret)> {
        todo!();
    }

    async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        todo!();
    }

    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        todo!();
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        todo!();
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    async fn verify(&self, key: &AccessKey) -> Result<()> {
        todo!();
    }

    async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        todo!();
    }

    fn lock(&mut self) {
        todo!();
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
