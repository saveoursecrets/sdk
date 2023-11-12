//! Gatekeeper manages access to a vault.
use crate::{
    crypto::{AccessKey, KeyDerivation, PrivateKey},
    decode, encode,
    events::{ReadEvent, WriteEvent},
    search::SearchIndex,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        SharedAccess, Summary, Vault, VaultAccess, VaultCommit, VaultEntry,
        VaultId, VaultMeta, VaultWriter,
    },
    vfs, Error, Result,
};
//use parking_lot::RwLock;

use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

use uuid::Uuid;

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
    /// Search index.
    index: Arc<RwLock<SearchIndex>>,
}

impl Gatekeeper {
    /// Create a new gatekeeper.
    pub fn new(
        vault: Vault,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: None,
            index: index
                .unwrap_or_else(|| Arc::new(RwLock::new(SearchIndex::new()))),
        }
    }

    /// Create a new gatekeeper that writes in-memory
    /// changes to a file.
    pub fn new_mirror(
        vault: Vault,
        mirror: VaultWriter<vfs::File>,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: Some(mirror),
            index: index
                .unwrap_or_else(|| Arc::new(RwLock::new(SearchIndex::new()))),
        }
    }

    /// Get the vault.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Get a mutable reference to the vault.
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// Replace this vault with a new updated vault
    /// and update the search index if possible.
    ///
    /// When a password is being changed then we need to use
    /// the new private key for the vault.
    pub async fn replace_vault(
        &mut self,
        vault: Vault,
        new_key: Option<PrivateKey>,
    ) -> Result<()> {
        let derived_key = new_key.as_ref().or(self.private_key.as_ref());

        if let Some(derived_key) = derived_key {
            let derived_key = Some(derived_key);
            let existing_keys = self.vault.keys().collect::<HashSet<_>>();
            let updated_keys = vault.keys().collect::<HashSet<_>>();

            let mut writer = self.index.write().await;

            for added_key in updated_keys.difference(&existing_keys) {
                if let Some((meta, secret)) = self
                    .read_secret(added_key, Some(&vault), derived_key)
                    .await?
                {
                    writer.add(self.vault().id(), added_key, meta, &secret);
                }
            }

            for deleted_key in existing_keys.difference(&updated_keys) {
                writer.remove(self.vault().id(), deleted_key);
            }

            for maybe_updated in updated_keys.union(&existing_keys) {
                if let (
                    Some(VaultCommit(existing_hash, _)),
                    Some(VaultCommit(updated_hash, _)),
                ) =
                    (self.vault.get(maybe_updated), vault.get(maybe_updated))
                {
                    if existing_hash != updated_hash {
                        if let Some((meta, secret)) = self
                            .read_secret(
                                maybe_updated,
                                Some(&vault),
                                derived_key,
                            )
                            .await?
                        {
                            writer.update(
                                self.vault().id(),
                                maybe_updated,
                                meta,
                                &secret,
                            );
                        }
                    }
                }
            }
        }

        self.vault = vault;
        Ok(())
    }

    /// Set the vault.
    pub fn set_vault(&mut self, vault: Vault) {
        self.vault = vault;
    }

    /// Get the search index.
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.index)
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
    ) -> Result<WriteEvent<'_>> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_name(name.clone()).await?;
        }
        self.vault.set_vault_name(name).await
    }

    /// Attempt to decrypt the meta data for the vault
    /// using the key assigned to this gatekeeper.
    pub async fn vault_meta(&self) -> Result<VaultMeta> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        if let Some(meta_aead) = self.vault.header().meta() {
            let meta_blob = self
                .vault
                .decrypt(private_key, meta_aead)
                .await
                .map_err(|_| Error::PassphraseVerification)?;
            let meta_data: VaultMeta = decode(&meta_blob).await?;
            Ok(meta_data)
        } else {
            Err(Error::VaultNotInit)
        }
    }

    /// Set the meta data for the vault.
    pub async fn set_vault_meta(
        &mut self,
        meta_data: VaultMeta,
    ) -> Result<WriteEvent<'_>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = encode(&meta_data).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_meta(Some(meta_aead.clone())).await?;
        }
        self.vault.set_vault_meta(Some(meta_aead)).await
    }

    /// Get a secret from the vault.
    async fn read_secret(
        &self,
        id: &SecretId,
        from: Option<&Vault>,
        private_key: Option<&PrivateKey>,
    ) -> Result<Option<(SecretMeta, Secret)>> {
        let private_key = private_key
            .or(self.private_key.as_ref())
            .ok_or(Error::VaultLocked)?;

        let from = from.unwrap_or(&self.vault);

        if let (Some(value), _payload) = from.read(id).await? {
            let VaultCommit(_commit, VaultEntry(meta_aead, secret_aead)) =
                value.as_ref();
            let meta_blob = from.decrypt(private_key, meta_aead).await?;
            let secret_meta: SecretMeta = decode(&meta_blob).await?;

            let secret_blob = from.decrypt(private_key, secret_aead).await?;
            let secret: Secret = decode(&secret_blob).await?;
            Ok(Some((secret_meta, secret)))
        } else {
            Ok(None)
        }
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
    pub async fn create(
        &mut self,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<WriteEvent<'_>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let vault_id = *self.vault().id();
        let id = Uuid::new_v4();

        //let reader = self.index.read().await;

        /*
        if reader
            .find_by_label(&vault_id, secret_meta.label(), None)
            .is_some()
        {
            return Err(Error::SecretAlreadyExists(
                secret_meta.label().to_string(),
            ));
        }
        */

        let meta_blob = encode(&secret_meta).await?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob).await?;

        let secret_blob = encode(&secret).await?;
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

        //drop(reader);

        let mut writer = self.index.write().await;
        writer.add(&vault_id, &id, secret_meta, &secret);

        Ok(result)
    }

    /// Get a secret and it's meta data from the vault.
    pub async fn read(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        let payload = ReadEvent::ReadSecret(*id);
        Ok(self
            .read_secret(id, None, None)
            .await?
            .map(|(meta, secret)| (meta, secret, payload)))
    }

    /// Update a secret in the vault.
    pub async fn update(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent<'_>>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        self.enforce_shared_readonly(private_key).await?;

        let vault_id = *self.vault().id();

        /*
        let reader = self.index.read().await;

        let doc = reader
            .find_by_id(&vault_id, id)
            .ok_or(Error::SecretDoesNotExist(*id))?;

        // Label has changed, so ensure uniqueness
        if doc.meta().label() != secret_meta.label()
            && reader
                .find_by_label(&vault_id, secret_meta.label(), Some(id))
                .is_some()
        {
            return Err(Error::SecretAlreadyExists(
                secret_meta.label().to_string(),
            ));
        }
        */

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

        let event = self
            .vault
            .update(id, commit, VaultEntry(meta_aead, secret_aead))
            .await?;

        //drop(reader);

        let mut writer = self.index.write().await;
        writer.update(&vault_id, id, secret_meta, &secret);

        Ok(event)
    }

    /// Delete a secret and it's meta data from the vault.
    pub async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent<'_>>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        self.enforce_shared_readonly(private_key).await?;

        let vault_id = *self.vault().id();
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.delete(id).await?;
        }
        let event = self.vault.delete(id).await?;
        let mut writer = self.index.write().await;
        writer.remove(&vault_id, id);
        Ok(event)
    }

    /// Verify an encryption passphrase.
    pub async fn verify(&self, key: &AccessKey) -> Result<()> {
        self.vault.verify(key).await
    }

    /// Add the meta data for the vault entries to a search index..
    pub async fn create_search_index(&mut self) -> Result<()> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let mut writer = self.index.write().await;
        for (id, value) in self.vault.iter() {
            let VaultCommit(_commit, VaultEntry(meta_aead, secret_aead)) =
                value;
            let meta_blob =
                self.vault.decrypt(private_key, meta_aead).await?;
            let secret_meta: SecretMeta = decode(&meta_blob).await?;

            let secret_blob =
                self.vault.decrypt(private_key, secret_aead).await?;
            let secret: Secret = decode(&secret_blob).await?;

            writer.add(self.vault().id(), id, secret_meta, &secret);
        }
        Ok(())
    }

    /// Unlock the vault by setting the private key from a passphrase.
    ///
    /// The private key is stored in memory by this gatekeeper.
    pub async fn unlock(&mut self, key: AccessKey) -> Result<VaultMeta> {
        if let Some(salt) = self.vault.salt() {
            match key {
                AccessKey::Password(passphrase) => {
                    let salt = KeyDerivation::parse_salt(salt)?;
                    let deriver = self.vault.deriver();
                    let private_key = deriver.derive(
                        &passphrase,
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
        self.private_key = None;
    }
}

impl From<Vault> for Gatekeeper {
    fn from(value: Vault) -> Self {
        Gatekeeper::new(value, None)
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
        vault::{secret::Secret, VaultBuilder},
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
            .password(passphrase.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(passphrase.into()).await?;

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

        if let WriteEvent::CreateSecret(secret_uuid, _) =
            keeper.create(secret_meta.clone(), secret.clone()).await?
        {
            let (saved_secret_meta, saved_secret) =
                keeper.read_secret(&secret_uuid, None, None).await?.unwrap();
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
            .password(passphrase.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(passphrase.into()).await?;

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

        let id = if let WriteEvent::CreateSecret(secret_uuid, _) =
            keeper.create(secret_meta.clone(), secret.clone()).await?
        {
            let (saved_secret_meta, saved_secret) =
                keeper.read_secret(&secret_uuid, None, None).await?.unwrap();
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

        keeper.update(&id, new_secret_meta, new_secret).await?;

        keeper.lock();

        Ok(())
    }
}
