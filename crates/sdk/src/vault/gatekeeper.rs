//! Gatekeeper manages access to a vault.
use crate::{
    crypto::{AccessKey, AeadPack, KeyDerivation, PrivateKey},
    decode, encode,
    events::{ReadEvent, WriteEvent},
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        SharedAccess, Summary, Vault, VaultAccess, VaultCommit, VaultEntry,
        VaultId, VaultMeta, VaultWriter,
    },
    vfs, Error, Result,
};

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
pub struct Gatekeeper {
    /// The private key.
    private_key: Option<PrivateKey>,
    /// The underlying vault.
    vault: Vault,
    /// Mirror in-memory vault changes to a writer.
    mirror: Option<VaultWriter<vfs::File>>,
}

impl Gatekeeper {
    /// Create a new gatekeeper.
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: None,
        }
    }

    /// Create a new gatekeeper that writes in-memory
    /// changes to a file.
    pub fn new_mirror(vault: Vault, mirror: VaultWriter<vfs::File>) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: Some(mirror),
        }
    }

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
    /// Callers should take care to lock beforehand and
    /// unlock again afterwards if the vault access key
    /// has been changed.
    pub async fn replace_vault(&mut self, vault: Vault) -> Result<()> {
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
    ) -> Result<WriteEvent> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_name(name.clone()).await?;
        }
        self.vault.set_vault_name(name).await
    }

    /// Attempt to decrypt the meta data for the vault
    /// using the key assigned to this gatekeeper.
    pub async fn vault_meta(&self) -> Result<VaultMeta> {
        if let Some(meta_aead) = self.vault.header().meta() {
            Ok(self.decrypt_meta(meta_aead).await?)
        } else {
            Err(Error::VaultNotInit)
        }
    }

    pub(crate) async fn decrypt_meta(
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
        decode(&meta_blob).await
    }

    /// Set the meta data for the vault.
    pub async fn set_vault_meta(
        &mut self,
        meta_data: &VaultMeta,
    ) -> Result<WriteEvent> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = encode(meta_data).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_meta(meta_aead.clone()).await?;
        }
        self.vault.set_vault_meta(meta_aead).await
    }

    pub(crate) async fn decrypt_secret(
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

    /// Ensure that if shared access is set to readonly that
    /// this user is allowed to write.
    async fn enforce_shared_readonly(&self, key: &PrivateKey) -> Result<()> {
        if let SharedAccess::ReadOnly(aead) = self.vault.shared_access() {
            self.vault
                .decrypt(key, aead)
                .await
                .map_err(|_| Error::PermissionDenied)?;
        }
        Ok(())
    }

    /// Add a secret to the vault.
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
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
                .insert(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        let result = self
            .vault
            .insert(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?;

        Ok(result)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        let event = ReadEvent::ReadSecret(*id);
        if let (Some(value), _payload) = self.vault.read(id).await? {
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
    ) -> Result<Option<WriteEvent>> {
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
                .update(
                    id,
                    commit,
                    VaultEntry(meta_aead.clone(), secret_aead.clone()),
                )
                .await?;
        }

        self.vault
            .update(id, commit, VaultEntry(meta_aead, secret_aead))
            .await
    }

    /// Delete a secret and it's meta data.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        self.enforce_shared_readonly(private_key).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.delete(id).await?;
        }
        self.vault.delete(id).await
    }

    /// Verify an encryption passphrase.
    pub async fn verify(&self, key: &AccessKey) -> Result<()> {
        self.vault.verify(key).await
    }

    /// Unlock the vault using the access key.
    ///
    /// The derived private key is stored in memory
    /// until [Gatekeeper::lock] is called.
    pub async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
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
            Err(Error::VaultNotInit)
        }
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    pub fn lock(&mut self) {
        tracing::debug!(folder = %self.id(), "drop_private_key");
        self.private_key = None;
    }
}

impl From<Vault> for Gatekeeper {
    fn from(value: Vault) -> Self {
        Gatekeeper::new(value)
    }
}

impl From<Gatekeeper> for Vault {
    fn from(value: Gatekeeper) -> Self {
        value.vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::test_utils::*;
    use crate::{
        constants::DEFAULT_VAULT_NAME,
        vault::{
            secret::{Secret, SecretRow},
            BuilderCredentials, VaultBuilder,
        },
    };
    use anyhow::Result;
    use secrecy::SecretString;

    #[tokio::test]
    async fn gatekeeper_secret_note() -> Result<()> {
        let passphrase = SecretString::new("mock-passphrase".to_owned());
        let name = String::from(DEFAULT_VAULT_NAME);
        let description = String::from("Mock Vault Description");

        let vault = VaultBuilder::new()
            .public_name(name)
            .description(description.clone())
            .build(BuilderCredentials::Password(passphrase.clone(), None))
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = passphrase.into();
        keeper.unlock(&key).await?;

        //// Decrypt the initialized meta data.
        let meta = keeper.vault_meta().await?;

        assert_eq!(&description, meta.description());

        let secret_label = "Mock Secret".to_string();
        let secret_value = "Super Secret Note".to_string();
        let secret = Secret::Note {
            text: SecretString::new(secret_value),
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(secret_label, secret.kind());

        let secret_data = SecretRow::new(
            SecretId::new_v4(),
            secret_meta.clone(),
            secret.clone(),
        );
        let event = keeper.create_secret(&secret_data).await?;
        if let WriteEvent::CreateSecret(secret_uuid, _) = event {
            let (saved_secret_meta, saved_secret, _) =
                keeper.read_secret(&secret_uuid).await?.unwrap();
            assert_eq!(secret, saved_secret);
            assert_eq!(secret_meta, saved_secret_meta);
        } else {
            panic!("test create secret got wrong payload variant");
        }

        keeper.lock();

        Ok(())
    }

    #[tokio::test]
    async fn gatekeeper_secret_account() -> Result<()> {
        let passphrase = SecretString::new("mock-passphrase".to_owned());
        let name = String::from(DEFAULT_VAULT_NAME);
        let description = String::from("Mock Vault Description");

        let vault = VaultBuilder::new()
            .public_name(name)
            .description(description.clone())
            .build(BuilderCredentials::Password(passphrase.clone(), None))
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = passphrase.into();
        keeper.unlock(&key).await?;

        //// Decrypt the initialized meta data.
        let meta = keeper.vault_meta().await?;

        assert_eq!(&description, meta.description());

        let secret_label = "Mock Account Secret".to_string();
        let secret_value = "super-secret-password".to_string();
        let secret = Secret::Account {
            account: "mock-username".to_string(),
            password: SecretString::new(secret_value),
            url: Some("https://example.com".parse()?),
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(secret_label, secret.kind());

        let id = SecretId::new_v4();
        let secret_data =
            SecretRow::new(id, secret_meta.clone(), secret.clone());
        let event = keeper.create_secret(&secret_data).await?;

        if let WriteEvent::CreateSecret(secret_uuid, _) = event {
            let (saved_secret_meta, saved_secret, _) =
                keeper.read_secret(&secret_uuid).await?.unwrap();
            assert_eq!(secret, saved_secret);
            assert_eq!(secret_meta, saved_secret_meta);
            secret_uuid
        } else {
            panic!("test create secret got wrong payload variant");
        };

        let new_secret_label = "Mock New Account".to_string();
        let new_secret_value = "new-secret-password".to_string();
        let new_secret = Secret::Account {
            account: "mock-new-username".to_string(),
            password: SecretString::new(new_secret_value),
            url: Some("https://example.com/new".parse()?),
            user_data: Default::default(),
        };
        let new_secret_meta =
            SecretMeta::new(new_secret_label.clone(), new_secret.kind());

        keeper
            .update_secret(&id, new_secret_meta, new_secret)
            .await?;

        keeper.lock();

        Ok(())
    }
}
