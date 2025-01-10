//! GateKeeper manages access to a vault.
use crate::{
    secret::{Secret, SecretMeta, SecretRow},
    Error, SharedAccess, Summary, Vault, VaultAccess, VaultMeta,
};
use async_trait::async_trait;
use sos_core::{
    crypto::{AccessKey, AeadPack, KeyDerivation, PrivateKey},
    decode, encode,
    events::{ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vfs as vfs;
use std::{borrow::Cow, path::PathBuf};

pub type VaultMirror<E> =
    Box<dyn VaultAccess<Error = E> + Send + Sync + 'static>;

/// Trait for types that manage read and write access to a vault.
#[async_trait]
pub trait Keeper {
    /// Error type.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static;

    /// Indicates whether the gatekeeper is mirroring
    /// changes to disc.
    fn is_mirror(&self) -> bool;

    /// Get the vault.
    fn vault(&self) -> &Vault;

    /// Mutable reference to the vault.
    fn vault_mut(&mut self) -> &mut Vault;

    /// Replace this vault with a new updated vault.
    ///
    /// Setting `write_disc` will write a new buffer to disc
    /// only when a mirror is enabled.
    ///
    /// Callers should take care to lock beforehand and
    /// unlock again afterwards if the vault access key
    /// has been changed.
    async fn replace_vault(
        &mut self,
        vault: Vault,
        write_disc: bool,
    ) -> Result<(), Self::Error>;

    /// Reload the vault from disc.
    ///
    /// Replaces the in-memory vault and updates the vault writer
    /// mirror when mirroring to disc is enabled.
    ///
    /// Use this to update the in-memory representation when a vault
    /// has been modified in a different process.
    ///
    /// Assumes the private key for the folder has not changed.
    async fn reload_vault(
        &mut self,
        path: &PathBuf,
    ) -> Result<(), Self::Error>;

    /// Set the vault.
    fn set_vault(&mut self, vault: Vault);

    /// Vault summary information.
    fn summary(&self) -> &Summary;

    /// Vault identifier.
    fn id(&self) -> &VaultId;

    /// Public name for the vault.
    fn name(&self) -> &str;

    /// Set the public name for the vault.
    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent, Self::Error>;

    /// Set the vault flags.
    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent, Self::Error>;

    /// Attempt to decrypt the meta data for the vault
    /// using the key assigned to this gatekeeper.
    async fn vault_meta(&self) -> Result<VaultMeta, Self::Error>;

    /*
    #[doc(hidden)]
    async fn decrypt_meta(
        &self,
        meta_aead: &AeadPack,
    ) -> Result<VaultMeta, Self::Error>;
    */

    /*
    #[doc(hidden)]
    pub async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret), E> {
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

    /// Set the meta data for the vault.
    async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent, Self::Error>;

    /*
    /// Ensure that if shared access is set to readonly that
    /// this user is allowed to write.
    async fn enforce_shared_readonly(
        &self,
        key: &PrivateKey,
    ) -> Result<(), Self::Error>;
    */

    /// Add a secret to the vault.
    async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent, Self::Error>;

    /// Read the encrypted contents of a secret.
    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent), Self::Error>;

    /// Get a secret and it's meta data.
    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>, Self::Error>;

    /// Update a secret.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>, Self::Error>;

    /// Delete a secret and it's meta data.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>, Self::Error>;

    /// Verify an encryption passphrase.
    async fn verify(&self, key: &AccessKey) -> Result<(), Self::Error>;

    /// Unlock the vault using the access key.
    ///
    /// The derived private key is stored in memory
    /// until [GateKeeper::lock] is called.
    async fn unlock(
        &mut self,
        key: &AccessKey,
    ) -> Result<VaultMeta, Self::Error>;

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    fn lock(&mut self);
}

/// Access to an in-memory vault optionally mirroring changes to disc.
///
/// It stores the derived private key in memory so should only be
/// used on client implementations.
///
/// Calling `lock()` will zeroize the private key in memory and prevent
/// any access to the vault until `unlock()` is called successfully.
///
/// To allow for meta data to be displayed before secret decryption
/// certain parts of a vault are encrypted separately which means that
/// technically it would be possible to use different private keys for
/// different secrets and for the meta data however this would be
/// a very poor user experience and would lead to confusion so the
/// gatekeeper is also responsible for ensuring the same private key
/// is used to encrypt the different chunks.
pub struct GateKeeper<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// The private key.
    private_key: Option<PrivateKey>,
    /// The underlying vault.
    vault: Vault,
    /// Mirror in-memory vault changes to a writer.
    mirror: Option<VaultMirror<E>>,
}

impl<E> GateKeeper<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new gatekeeper.
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: None,
        }
    }

    /// Create a new gatekeeper that writes in-memory
    /// changes to a mirror.
    pub fn new_mirror(vault: Vault, mirror: VaultMirror<E>) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: Some(mirror),
        }
    }

    /*
    /// Indicates whether the gatekeeper is mirroring
    /// changes to disc.
    pub fn is_mirror(&self) -> bool {
        self.mirror.is_some()
    }

    /// Get the vault.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Get a mutable reference to the vault.
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// Replace this vault with a new updated vault.
    ///
    /// Setting `write_disc` will write a new buffer to disc
    /// only when a mirror is enabled.
    ///
    /// Callers should take care to lock beforehand and
    /// unlock again afterwards if the vault access key
    /// has been changed.
    pub async fn replace_vault(
        &mut self,
        vault: Vault,
        write_disc: bool,
    ) -> Result<(), E> {
        if let (true, Some(mirror)) = (write_disc, &mut self.mirror) {
            mirror.replace_vault(&vault).await?;
        }
        self.vault = vault;
        Ok(())
    }

    /// Reload the vault from disc.
    ///
    /// Replaces the in-memory vault and updates the vault writer
    /// mirror when mirroring to disc is enabled.
    ///
    /// Use this to update the in-memory representation when a vault
    /// has been modified in a different process.
    ///
    /// Assumes the private key for the folder has not changed.
    pub async fn reload_vault(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<(), E> {
        let buffer = vfs::read(path.as_ref()).await?;
        let vault: Vault = decode(&buffer).await?;
        if let Some(mirror) = &mut self.mirror {
            mirror.replace_vault(&vault).await?;
        }
        self.vault = vault;
        Ok(())
    }

    /// Set the vault.
    pub fn set_vault(&mut self, vault: Vault) {
        self.vault = vault;
    }

    /// Get the summary for the vault.
    pub fn summary(&self) -> &Summary {
        self.vault.summary()
    }

    /// Get the identifier for the vault.
    pub fn id(&self) -> &VaultId {
        self.vault.id()
    }

    /// Get the public name for the vault.
    pub fn name(&self) -> &str {
        self.vault.name()
    }

    /// Set the public name for the vault.
    pub async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent, E> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_name(name.clone()).await?;
        }
        Ok(self.vault.set_vault_name(name).await?)
    }

    /// Set the vault flags.
    pub async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent, E> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_flags(flags.clone()).await?;
        }
        Ok(self.vault.set_vault_flags(flags).await?)
    }

    /// Attempt to decrypt the meta data for the vault
    /// using the key assigned to this gatekeeper.
    pub async fn vault_meta(&self) -> Result<VaultMeta, E> {
        if let Some(meta_aead) = self.vault.header().meta() {
            Ok(self.decrypt_meta(meta_aead).await?)
        } else {
            Err(Error::VaultNotInit.into())
        }
    }
    */

    #[doc(hidden)]
    pub async fn decrypt_meta(
        &self,
        meta_aead: &AeadPack,
    ) -> Result<VaultMeta, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = self
            .vault
            .decrypt(private_key, meta_aead)
            .await
            .map_err(|_| Error::PassphraseVerification)?;
        Ok(decode(&meta_blob).await?)
    }

    /*
    /// Set the meta data for the vault.
    pub async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = encode(meta_data).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_meta(meta_aead.clone()).await?;
        }
        Ok(self.vault.set_vault_meta(meta_aead).await?)
    }
    */

    #[doc(hidden)]
    pub async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret), E> {
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

    /// Ensure that if shared access is set to readonly that
    /// this user is allowed to write.
    async fn enforce_shared_readonly(
        &self,
        key: &PrivateKey,
    ) -> Result<(), E> {
        if let SharedAccess::ReadOnly(aead) = self.vault.shared_access() {
            self.vault
                .decrypt(key, aead)
                .await
                .map_err(|_| Error::PermissionDenied)?;
        }
        Ok(())
    }

    /*
    /// Add a secret to the vault.
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let id = *secret_data.id();
        let meta_blob = encode(secret_data.meta()).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;

        let secret_blob = encode(secret_data.secret()).await?;
        let secret_aead =
            self.vault.encrypt(private_key, &secret_blob).await?;

        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;

        if let Some(mirror) = self.mirror.as_mut() {
            mirror
                .insert_secret(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        let result = self
            .vault
            .insert_secret(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?;

        Ok(result)
    }

    /// Read the encrypted contents of a secret.
    pub async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent), E> {
        Ok(self.vault.read_secret(id).await?)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>, E> {
        if let (Some(value), event) = self.raw_secret(id).await? {
            let (meta, secret) = self
                .decrypt_secret(value.as_ref(), self.private_key.as_ref())
                .await?;
            Ok(Some((meta, secret, event)))
        } else {
            Ok(None)
        }
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let meta_blob = encode(&secret_meta).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;

        let secret_blob = encode(&secret).await?;
        let secret_aead =
            self.vault.encrypt(private_key, &secret_blob).await?;

        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;

        if let Some(mirror) = self.mirror.as_mut() {
            mirror
                .update_secret(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        Ok(self
            .vault
            .update_secret(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?)
    }

    /// Delete a secret and it's meta data.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        self.enforce_shared_readonly(private_key).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.delete_secret(id).await?;
        }
        Ok(self.vault.delete_secret(id).await?)
    }

    /// Verify an encryption passphrase.
    pub async fn verify(&self, key: &AccessKey) -> Result<(), E> {
        Ok(self.vault.verify(key).await?)
    }

    /// Unlock the vault using the access key.
    ///
    /// The derived private key is stored in memory
    /// until [GateKeeper::lock] is called.
    pub async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta, E> {
        if let Some(salt) = self.vault.salt() {
            match key {
                AccessKey::Password(passphrase) => {
                    let salt = KeyDerivation::parse_salt(salt)?;
                    let deriver = self.vault.deriver();
                    let private_key = deriver.derive(
                        passphrase,
                        &salt,
                        self.vault.seed(),
                    )?;
                    self.private_key =
                        Some(PrivateKey::Symmetric(private_key));
                    self.vault_meta().await
                }
                AccessKey::Identity(id) => {
                    self.private_key =
                        Some(PrivateKey::Asymmetric(id.clone()));
                    self.vault_meta().await
                }
            }
        } else {
            Err(Error::VaultNotInit.into())
        }
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    pub fn lock(&mut self) {
        tracing::debug!(folder = %self.id(), "drop_private_key");
        self.private_key = None;
    }
    */
}

#[async_trait]
impl<E> Keeper for GateKeeper<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    fn is_mirror(&self) -> bool {
        self.mirror.is_some()
    }

    fn vault(&self) -> &Vault {
        &self.vault
    }

    fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    async fn replace_vault(
        &mut self,
        vault: Vault,
        write_disc: bool,
    ) -> Result<(), E> {
        if let (true, Some(mirror)) = (write_disc, &mut self.mirror) {
            mirror.replace_vault(&vault).await?;
        }
        self.vault = vault;
        Ok(())
    }

    async fn reload_vault(&mut self, path: &PathBuf) -> Result<(), E> {
        let buffer = vfs::read(path).await?;
        let vault: Vault = decode(&buffer).await?;
        if let Some(mirror) = &mut self.mirror {
            mirror.replace_vault(&vault).await?;
        }
        self.vault = vault;
        Ok(())
    }

    fn set_vault(&mut self, vault: Vault) {
        self.vault = vault;
    }

    fn summary(&self) -> &Summary {
        self.vault.summary()
    }

    fn id(&self) -> &VaultId {
        self.vault.id()
    }

    fn name(&self) -> &str {
        self.vault.name()
    }

    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent, E> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_name(name.clone()).await?;
        }
        Ok(self.vault.set_vault_name(name).await?)
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent, E> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_flags(flags.clone()).await?;
        }
        Ok(self.vault.set_vault_flags(flags).await?)
    }

    async fn vault_meta(&self) -> Result<VaultMeta, E> {
        if let Some(meta_aead) = self.vault.header().meta() {
            Ok(self.decrypt_meta(meta_aead).await?)
        } else {
            Err(Error::VaultNotInit.into())
        }
    }

    /*
    #[doc(hidden)]
    pub async fn decrypt_meta(
        &self,
        meta_aead: &AeadPack,
    ) -> Result<VaultMeta, E> {
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
    ) -> Result<WriteEvent, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = encode(meta_data).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_meta(meta_aead.clone()).await?;
        }
        Ok(self.vault.set_vault_meta(meta_aead).await?)
    }

    /*
    #[doc(hidden)]
    pub async fn decrypt_secret(
        &self,
        vault_commit: &VaultCommit,
        private_key: Option<&PrivateKey>,
    ) -> Result<(SecretMeta, Secret), E> {
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
    ) -> Result<(), E> {
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
    ) -> Result<WriteEvent, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let id = *secret_data.id();
        let meta_blob = encode(secret_data.meta()).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;

        let secret_blob = encode(secret_data.secret()).await?;
        let secret_aead =
            self.vault.encrypt(private_key, &secret_blob).await?;

        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;

        if let Some(mirror) = self.mirror.as_mut() {
            mirror
                .insert_secret(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        let result = self
            .vault
            .insert_secret(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?;

        Ok(result)
    }

    /// Read the encrypted contents of a secret.
    async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent), E> {
        Ok(self.vault.read_secret(id).await?)
    }

    /// Get a secret and it's meta data.
    async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>, E> {
        if let (Some(value), event) = self.raw_secret(id).await? {
            let (meta, secret) = self
                .decrypt_secret(value.as_ref(), self.private_key.as_ref())
                .await?;
            Ok(Some((meta, secret, event)))
        } else {
            Ok(None)
        }
    }

    /// Update a secret.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let meta_blob = encode(&secret_meta).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;

        let secret_blob = encode(&secret).await?;
        let secret_aead =
            self.vault.encrypt(private_key, &secret_blob).await?;

        let (commit, _) =
            Vault::commit_hash(&meta_aead, &secret_aead).await?;

        if let Some(mirror) = self.mirror.as_mut() {
            mirror
                .update_secret(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        Ok(self
            .vault
            .update_secret(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?)
    }

    /// Delete a secret and it's meta data.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>, E> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        self.enforce_shared_readonly(private_key).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.delete_secret(id).await?;
        }
        Ok(self.vault.delete_secret(id).await?)
    }

    /// Verify an encryption passphrase.
    async fn verify(&self, key: &AccessKey) -> Result<(), E> {
        Ok(self.vault.verify(key).await?)
    }

    /// Unlock the vault using the access key.
    ///
    /// The derived private key is stored in memory
    /// until [GateKeeper::lock] is called.
    async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta, E> {
        if let Some(salt) = self.vault.salt() {
            match key {
                AccessKey::Password(passphrase) => {
                    let salt = KeyDerivation::parse_salt(salt)?;
                    let deriver = self.vault.deriver();
                    let private_key = deriver.derive(
                        passphrase,
                        &salt,
                        self.vault.seed(),
                    )?;
                    self.private_key =
                        Some(PrivateKey::Symmetric(private_key));
                    self.vault_meta().await
                }
                AccessKey::Identity(id) => {
                    self.private_key =
                        Some(PrivateKey::Asymmetric(id.clone()));
                    self.vault_meta().await
                }
            }
        } else {
            Err(Error::VaultNotInit.into())
        }
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    fn lock(&mut self) {
        tracing::debug!(folder = %self.id(), "drop_private_key");
        self.private_key = None;
    }
}

impl<E> From<Vault> for GateKeeper<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    fn from(value: Vault) -> Self {
        GateKeeper::<E>::new(value)
    }
}

impl<E> From<GateKeeper<E>> for Vault
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    fn from(value: GateKeeper<E>) -> Self {
        value.vault
    }
}
