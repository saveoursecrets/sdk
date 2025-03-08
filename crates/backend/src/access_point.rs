use crate::{BackendTarget, Error, Result};
use async_trait::async_trait;
use sos_core::{
    crypto::{AccessKey, AeadPack, PrivateKey},
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultFlags, VaultId,
};
use sos_database::VaultDatabaseWriter;
use sos_filesystem::VaultFileWriter;
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    AccessPoint, SecretAccess, Summary, Vault, VaultMeta,
};
use std::path::Path;

/// Backend storage access point.
pub struct BackendAccessPoint(AccessPoint<Error>);

impl BackendAccessPoint {
    /// Wrap an access point.
    pub fn wrap(access_point: AccessPoint<Error>) -> Self {
        Self(access_point)
    }

    /// In-memory access point from a vault.
    pub fn from_vault(vault: Vault) -> Self {
        Self(AccessPoint::<Error>::new(vault))
    }

    /// Access point for a folder in a backend target.
    ///
    /// Changes are mirrored to the backend target.
    pub async fn new(target: BackendTarget, vault: Vault) -> Self {
        match target {
            BackendTarget::FileSystem(paths) => {
                let path = paths.vault_path(vault.id());
                Self::from_path(path, vault)
            }
            BackendTarget::Database(_, client) => {
                let mirror =
                    VaultDatabaseWriter::<Error>::new(client, *vault.id());
                Self(AccessPoint::<Error>::new_mirror(
                    vault,
                    Box::new(mirror),
                ))
            }
        }
    }

    /// Access point that mirrors to disc.
    pub fn from_path<P: AsRef<Path>>(path: P, vault: Vault) -> Self {
        let mirror = VaultFileWriter::<Error>::new(path);
        Self(AccessPoint::<Error>::new_mirror(vault, Box::new(mirror)))
    }
}

#[async_trait]
impl SecretAccess for BackendAccessPoint {
    type Error = Error;

    fn is_mirror(&self) -> bool {
        self.0.is_mirror()
    }

    fn vault(&self) -> &Vault {
        self.0.vault()
    }

    async fn replace_vault(
        &mut self,
        vault: Vault,
        mirror_changes: bool,
    ) -> Result<()> {
        Ok(self.0.replace_vault(vault, mirror_changes).await?)
    }

    async fn reload_vault<P: AsRef<Path> + Send>(
        &mut self,
        path: P,
    ) -> Result<()> {
        Ok(self.0.reload_vault(path).await?)
    }

    fn summary(&self) -> &Summary {
        self.0.summary()
    }

    fn id(&self) -> &VaultId {
        self.0.id()
    }

    fn name(&self) -> &str {
        self.0.name()
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        Ok(self.0.set_vault_name(name).await?)
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        Ok(self.0.set_vault_flags(flags).await?)
    }

    async fn vault_meta(&self) -> Result<VaultMeta> {
        Ok(self.0.vault_meta().await?)
    }

    /// Set the meta data for the vault.
    async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent> {
        Ok(self.0.set_vault_meta(meta_data).await?)
    }

    async fn decrypt_meta(&self, meta_aead: &AeadPack) -> Result<VaultMeta> {
        Ok(self.0.decrypt_meta(meta_aead).await?)
    }

    async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret)> {
        Ok(self.0.decrypt_secret(vault_commit, private_key).await?)
    }

    async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        Ok(self.0.create_secret(secret_data).await?)
    }

    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(VaultCommit, ReadEvent)>> {
        Ok(self.0.raw_secret(id).await?)
    }

    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        Ok(self.0.read_secret(id).await?)
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        Ok(self.0.update_secret(id, meta, secret).await?)
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        Ok(self.0.delete_secret(id).await?)
    }

    async fn verify(&self, key: &AccessKey) -> Result<()> {
        Ok(self.0.verify(key).await?)
    }

    async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        Ok(self.0.unlock(key).await?)
    }

    fn lock(&mut self) {
        self.0.lock();
    }
}

impl From<BackendAccessPoint> for Vault {
    fn from(value: BackendAccessPoint) -> Self {
        value.0.into()
    }
}
