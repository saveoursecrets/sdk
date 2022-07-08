//! Gatekeeper manages access to a vault.
use crate::{
    crypto::{secret_key::SecretKey, AeadPack},
    decode, encode,
    events::SyncEvent,
    secret::{Secret, SecretId, SecretMeta, SecretRef, VaultMeta},
    vault::{Summary, Vault, VaultAccess, VaultCommit, VaultEntry, VaultId},
    Error, Result,
};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

/// Access to an in-memory vault optionally mirroring changes to disc.
///
/// It stores the private key in memory so should only be used on client
/// implementations.
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
#[derive(Default)]
pub struct Gatekeeper {
    /// The private key.
    private_key: Option<SecretKey>,
    /// The underlying vault.
    vault: Vault,
    /// Mirror for in-memory vault changes.
    mirror: Option<Box<dyn VaultAccess + Send + Sync>>,
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

    /// Create a new gatekeeper with a mirror.
    pub fn new_mirror(
        vault: Vault,
        mirror: Box<dyn VaultAccess + Send + Sync>,
    ) -> Self {
        Self {
            vault,
            private_key: None,
            mirror: Some(mirror),
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
    pub fn set_vault_name(&mut self, name: String) -> Result<SyncEvent<'_>> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_name(name.clone())?;
        }
        self.vault.set_vault_name(name)
    }

    /// Initialize the vault with the given label and password.
    pub fn initialize<S: AsRef<str>>(
        &mut self,
        name: String,
        label: String,
        password: S,
    ) -> Result<()> {
        // Initialize the private key and store the salt
        let private_key = self.vault.initialize(password.as_ref())?;
        self.private_key = Some(private_key);

        // Assign the label to the meta data
        let mut init_meta_data: VaultMeta = Default::default();
        init_meta_data.set_label(label);
        self.set_meta(init_meta_data)?;

        self.vault.set_name(name);
        Ok(())
    }

    /// Attempt to decrypt the index meta data and extract the label.
    pub fn label(&self) -> Result<String> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        if let Some(meta_aead) = self.vault.header().meta() {
            let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
            let meta_data: VaultMeta = decode(&meta_blob)?;
            Ok(meta_data.label().to_string())
        } else {
            Err(Error::VaultNotInit)
        }
    }

    /// Attempt to decrypt the secrets meta data.
    pub fn meta_data(&self) -> Result<HashMap<&SecretId, SecretMeta>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        if self.vault.header().meta().is_some() {
            let mut result = HashMap::new();
            for (id, meta_aead) in self.vault.meta_data() {
                let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
                let secret_meta: SecretMeta = decode(&meta_blob)?;
                result.insert(id, secret_meta);
            }
            Ok(result)
        } else {
            Err(Error::VaultNotInit)
        }
    }

    /// Attempt to decrypt the index meta data for the vault
    /// using the passphrase assigned to this gatekeeper.
    pub fn vault_meta(&self) -> Result<VaultMeta> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        if let Some(meta_aead) = self.vault.header().meta() {
            let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
            let meta_data: VaultMeta = decode(&meta_blob)?;
            Ok(meta_data)
        } else {
            Err(Error::VaultNotInit)
        }
    }

    /// Set the meta data for the vault.
    // TODO: rename to set_vault_meta() for consistency
    fn set_meta(&mut self, meta_data: VaultMeta) -> Result<SyncEvent<'_>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        let meta_blob = encode(&meta_data)?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.set_vault_meta(Some(meta_aead.clone()))?;
        }
        self.vault.set_vault_meta(Some(meta_aead))
    }

    /// Get a secret from the vault.
    fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret)>> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        if let (Some(value), _payload) = self.vault.read(id)? {
            let VaultCommit(_commit, VaultEntry(meta_aead, secret_aead)) =
                value.as_ref();
            let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
            let secret_meta: SecretMeta = decode(&meta_blob)?;

            let secret_blob = self.vault.decrypt(private_key, secret_aead)?;
            let secret: Secret = decode(&secret_blob)?;
            Ok(Some((secret_meta, secret)))
        } else {
            Ok(None)
        }
    }

    /// Find secret meta by label.
    pub fn find_by_label<'a>(
        &self,
        meta_data: &'a HashMap<&'a SecretId, SecretMeta>,
        label: &str,
    ) -> Option<&'a SecretMeta> {
        meta_data.values().find(|m| m.label() == label)
    }

    /// Find secret meta by uuid or label.
    pub fn find_by_uuid_or_label<'a>(
        &self,
        meta_data: &'a HashMap<&'a SecretId, SecretMeta>,
        target: &'a SecretRef,
    ) -> Option<(&'a SecretId, &'a SecretMeta)> {
        match target {
            SecretRef::Id(id) => meta_data.get(id).map(|v| (id, v)),
            SecretRef::Name(name) => meta_data.iter().find_map(|(k, v)| {
                if v.label() == name {
                    Some((*k, v))
                } else {
                    None
                }
            }),
        }
    }

    /// Add a secret to the vault.
    pub fn create(
        &mut self,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>> {
        // TODO: use cached in-memory meta data
        let meta = self.meta_data()?;

        if self.find_by_label(&meta, secret_meta.label()).is_some() {
            return Err(Error::SecretAlreadyExists(
                secret_meta.label().to_string(),
            ));
        }

        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        let meta_blob = encode(&secret_meta)?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;

        let secret_blob = encode(&secret)?;
        let secret_aead = self.vault.encrypt(private_key, &secret_blob)?;

        let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
        let id = Uuid::new_v4();

        if let Some(mirror) = self.mirror.as_mut() {
            mirror.insert(
                id,
                commit.clone(),
                VaultEntry(meta_aead.clone(), secret_aead.clone()),
            )?;
        }

        Ok(self.vault.insert(
            id,
            commit,
            VaultEntry(meta_aead, secret_aead),
        )?)
    }

    /// Get a secret and it's meta data from the vault.
    pub fn read(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, SyncEvent<'_>)>> {
        let payload = SyncEvent::ReadSecret(*id);
        Ok(self
            .read_secret(id)?
            .map(|(meta, secret)| (meta, secret, payload)))
    }

    /// Update a secret in the vault.
    pub fn update(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<SyncEvent<'_>>> {
        // TODO: use cached in-memory meta data
        let meta = self.meta_data()?;

        let existing_meta = meta.get(id);

        if existing_meta.is_none() {
            return Err(Error::SecretDoesNotExist(*id));
        }

        let existing_meta = existing_meta.unwrap();

        // Label has changed, so ensure uniqueness
        if existing_meta.label() != secret_meta.label()
            && self.find_by_label(&meta, secret_meta.label()).is_some()
        {
            return Err(Error::SecretAlreadyExists(
                secret_meta.label().to_string(),
            ));
        }

        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;

        let meta_blob = encode(&secret_meta)?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;

        let secret_blob = encode(&secret)?;
        let secret_aead = self.vault.encrypt(private_key, &secret_blob)?;

        let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;

        if let Some(mirror) = self.mirror.as_mut() {
            mirror.update(
                id,
                commit.clone(),
                VaultEntry(meta_aead.clone(), secret_aead.clone()),
            )?;
        }

        Ok(self.vault.update(
            id,
            commit,
            VaultEntry(meta_aead, secret_aead),
        )?)
    }

    /// Delete a secret and it's meta data from the vault.
    pub fn delete(&mut self, id: &SecretId) -> Result<Option<SyncEvent<'_>>> {
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.delete(id)?;
        }
        self.vault.delete(id)
    }

    /// Decrypt secret meta data.
    pub fn decrypt_meta(&self, meta_aead: &AeadPack) -> Result<SecretMeta> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
        let secret_meta: SecretMeta = decode(&meta_blob)?;
        Ok(secret_meta)
    }

    /// Encrypt secret meta data.
    pub fn encrypt_meta(&self, secret_meta: &SecretMeta) -> Result<AeadPack> {
        let private_key =
            self.private_key.as_ref().ok_or(Error::VaultLocked)?;
        let meta_blob = encode(secret_meta)?;
        let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;
        Ok(meta_aead)
    }

    /// Unlock the vault by setting the private key from a passphrase.
    ///
    /// The private key is stored in memory by this gatekeeper.
    pub fn unlock<S: AsRef<str>>(
        &mut self,
        passphrase: S,
    ) -> Result<VaultMeta> {
        if let Some(salt) = self.vault.salt() {
            let salt = SecretKey::parse_salt(salt)?;
            let private_key = SecretKey::derive_32(passphrase, &salt)?;
            self.private_key = Some(private_key);
            self.vault_meta()
        } else {
            Err(Error::VaultNotInit)
        }
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    pub fn lock(&mut self) {
        if let Some(private_key) = self.private_key.as_mut() {
            private_key.zeroize();
        }
        self.private_key = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secret::Secret,
        vault::{Vault, DEFAULT_VAULT_NAME},
    };
    use anyhow::Result;

    #[test]
    fn gatekeeper_secret_note() -> Result<()> {
        let passphrase = "mock-passphrase";
        let vault: Vault = Default::default();
        let mut keeper = Gatekeeper::new(vault);

        let name = String::from(DEFAULT_VAULT_NAME);
        let label = String::from("Mock Vault Label");
        keeper.initialize(name, label.clone(), passphrase)?;

        //// Decrypt the initialized meta data.
        let meta = keeper.vault_meta()?;

        assert_eq!(&label, meta.label());

        let secret_label = String::from("Mock Secret");
        let secret_value = String::from("Super Secret Note");
        let secret = Secret::Note(secret_value);
        let secret_meta = SecretMeta::new(secret_label, secret.kind());

        if let SyncEvent::CreateSecret(secret_uuid, _) =
            keeper.create(secret_meta.clone(), secret.clone())?
        {
            let (saved_secret_meta, saved_secret) =
                keeper.read_secret(&secret_uuid)?.unwrap();
            assert_eq!(secret, saved_secret);
            assert_eq!(secret_meta, saved_secret_meta);
        } else {
            panic!("test create secret got wrong payload variant");
        }

        keeper.lock();

        Ok(())
    }
}
