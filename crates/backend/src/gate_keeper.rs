use crate::{Error, Result};
use async_trait::async_trait;
use sos_core::{
    commit::CommitHash,
    crypto::{AccessKey, AeadPack},
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    GateKeeper, Keeper, Summary, Vault, VaultMeta,
};
use std::borrow::Cow;
use std::path::PathBuf;

/// Gate keeper implementation.
pub enum BackendGateKeeper {
    /// File system.
    FileSystem(GateKeeper<Error>),
}

#[async_trait]
impl Keeper for BackendGateKeeper {
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
        write_disc: bool,
    ) -> Result<()> {
        todo!();
    }

    async fn reload_vault(&mut self, path: &PathBuf) -> Result<()> {
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

    /*
    #[doc(hidden)]
    pub async fn decrypt_meta(
        &self,
        meta_aead: &AeadPack,
    ) -> Result<VaultMeta> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = self
            .vault
            .decrypt(private_key, meta_aead)
            .await
            .map_err(|_| Error::PassphraseVerification)?;
        Ok(decode(&meta_blob).await?)
    }
    */

    /// Set the meta data for the vault.
    async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /*
    #[doc(hidden)]
    pub async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret)> {
        let private_key = private_key
            .or(self.private_key.as_ref())
            .ok_or(Error::VaultLocked)?;

        let VaultCommit(_commit, VaultEntry(meta_aead, secret_aead)) =
            vault_commit;
        let meta_blob = self.vault.decrypt(private_key, meta_aead).await?;
        let secret_meta: SecretMeta = decode(&meta_blob).await?;

        let secret_blob =
            self.vault.decrypt(private_key, secret_aead).await?;
        let secret: Secret = decode(&secret_blob).await?;
        Ok((secret_meta, secret))
    }
    */

    /*
    /// Ensure that if shared access is set to readonly that
    /// this user is allowed to write.
    async fn enforce_shared_readonly(
        &self,
        key: &PrivateKey,
    ) -> Result<()> {
        if let SharedAccess::ReadOnly(aead) = self.vault.shared_access() {
            self.vault
                .decrypt(key, aead)
                .await
                .map_err(|_| Error::PermissionDenied)?;
        }
        Ok(())
    }
    */

    /// Add a secret to the vault.
    async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /// Read the encrypted contents of a secret.
    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        todo!();
    }

    /// Get a secret and it's meta data.
    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        todo!();
    }

    /// Update a secret.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    /// Delete a secret and it's meta data.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    /// Verify an encryption passphrase.
    async fn verify(&self, key: &AccessKey) -> Result<()> {
        todo!();
    }

    /// Unlock the vault using the access key.
    ///
    /// The derived private key is stored in memory
    /// until [GateKeeper::lock] is called.
    async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        todo!();
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    fn lock(&mut self) {
        todo!();
    }
}

impl From<BackendGateKeeper> for Vault {
    fn from(value: BackendGateKeeper) -> Self {
        match value {
            BackendGateKeeper::FileSystem(inner) => inner.into(),
        }
    }
}
