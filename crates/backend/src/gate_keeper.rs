use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    crypto::{AccessKey, AeadPack, PrivateKey},
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultFlags, VaultId,
};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    SecretAccess, Summary, Vault, AccessPoint, VaultMeta,
};
use std::borrow::Cow;
use std::path::Path;

/// Backend access point implementation.
pub enum BackendAccessPoint {
    /// File system.
    FileSystem(AccessPoint<Error>),
}

impl BackendAccessPoint {
    /// New access point from a vault.
    pub fn new_vault(vault: Vault) -> Self {
        Self::FileSystem(AccessPoint::<Error>::new(vault))
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
            BackendAccessPoint::FileSystem(inner) => inner.into(),
        }
    }
}
