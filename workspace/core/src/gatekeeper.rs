//! Gatekeeper manages access to a vault.
//!
//! It stores the private key in memory so should only be used on client
//! implementations.
//!
//! Calling `lock()` will zeroize the private key in memory and prevent
//! any access to the vault until `unlock()` is called successfully.
//!
//! To allow for meta data to be displayed before secret decryption
//! certain parts of a vault are encrypted separately which means that
//! technically it would be possible to use different private keys for
//! different secrets and for the meta data however this would be
//! a very poor user experience and would lead to confusion so the
//! gatekeeper is also responsible for ensuring the same private key
//! is used to encrypt the different chunks.
//!
use crate::{
    crypto::secret_key::SecretKey,
    decode, encode,
    secret::{Secret, SecretMeta, VaultMeta},
    vault::Vault,
    Error, Result,
};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

/// Manage access to a vault's secrets.
#[derive(Default)]
pub struct Gatekeeper {
    /// The private key.
    private_key: Option<Box<SecretKey>>,
    /// The underlying vault.
    vault: Vault,
}

impl Gatekeeper {
    /// Create a new gatekeeper.
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            private_key: None,
        }
    }

    /// Get the vault.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Set the vault.
    pub fn set_vault(&mut self, vault: Vault) {
        self.vault = vault;
    }

    /// Get the identifier for the vault.
    pub fn id(&self) -> &Uuid {
        self.vault.id()
    }

    /// Get the public name for the vault.
    pub fn name(&self) -> &str {
        self.vault.name()
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
        self.private_key = Some(Box::new(private_key));

        // Assign the label to the meta data
        let mut init_meta_data: VaultMeta = Default::default();
        init_meta_data.set_label(label);
        self.set_meta(init_meta_data)?;

        self.vault.set_name(name);
        Ok(())
    }

    /// Attempt to decrypt the index meta data and extract the label.
    pub fn label(&self) -> Result<String> {
        if let Some(private_key) = &self.private_key {
            if let Some(meta_aead) = self.vault.header().meta() {
                let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
                let meta_data: VaultMeta = decode(meta_blob)?;
                Ok(meta_data.label().to_string())
            } else {
                Err(Error::VaultNotInit)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Attempt to decrypt the secrets meta data.
    pub fn meta_data(&self) -> Result<HashMap<&Uuid, SecretMeta>> {
        if let Some(private_key) = &self.private_key {
            if let Some(meta_aead) = self.vault.header().meta() {
                let mut result = HashMap::new();
                for (uuid, meta_aead) in self.vault.meta_data() {
                    let meta_blob =
                        self.vault.decrypt(private_key, meta_aead)?;
                    let secret_meta: SecretMeta = decode(meta_blob)?;
                    result.insert(uuid, secret_meta);
                }
                Ok(result)
            } else {
                Err(Error::VaultNotInit)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Attempt to decrypt the index meta data for the vault
    /// using the passphrase assigned to this gatekeeper.
    pub fn meta(&self) -> Result<VaultMeta> {
        if let Some(private_key) = &self.private_key {
            if let Some(meta_aead) = self.vault.header().meta() {
                let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
                let meta_data: VaultMeta = decode(meta_blob)?;
                Ok(meta_data)
            } else {
                Err(Error::VaultNotInit)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Set the meta data for the vault.
    fn set_meta(&mut self, meta_data: VaultMeta) -> Result<()> {
        if let Some(private_key) = &self.private_key {
            let meta_blob = encode(&meta_data)?;
            let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;
            self.vault.header_mut().set_meta(Some(meta_aead));
            Ok(())
        } else {
            Err(Error::VaultLocked)
        }
    }

    /*
    /// Set the meta data for a secret.
    fn set_secret_meta(
        &mut self,
        uuid: Uuid,
        meta_data: SecretMeta,
    ) -> Result<()> {
        let mut meta = self.meta()?;
        meta.add_secret_meta(uuid, meta_data);
        self.set_meta(meta)?;
        Ok(())
    }
    */

    /// Get the meta data for a secret.
    fn get_secret_meta(&self, uuid: &Uuid) -> Result<Option<SecretMeta>> {
        if let Some(private_key) = &self.private_key {
            if let Some((meta_aead, _)) = self.vault.get_secret(uuid) {
                let meta_blob = self.vault.decrypt(private_key, meta_aead)?;
                let secret: SecretMeta = decode(meta_blob)?;
                Ok(Some(secret))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Get a secret from the vault.
    fn get_secret(&self, uuid: &Uuid) -> Result<Option<Secret>> {
        if let Some(private_key) = &self.private_key {
            if let Some((_, secret_aead)) = self.vault.get_secret(uuid) {
                let secret_blob =
                    self.vault.decrypt(private_key, secret_aead)?;
                let secret: Secret = decode(secret_blob)?;
                Ok(Some(secret))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Add a secret to the vault.
    pub fn create(
        &mut self,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Uuid> {
        let uuid = Uuid::new_v4();

        /*
        let mut meta = self.meta()?;

        if meta.find_by_label(secret_meta.label()).is_some() {
            return Err(Error::SecretAlreadyExists(
                secret_meta.label().to_string(),
            ));
        }
        */

        //meta.add_secret_meta(uuid, secret_meta);
        //self.set_meta(meta)?;

        if let Some(private_key) = &self.private_key {
            let meta_blob = encode(&secret_meta)?;
            let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;

            let secret_blob = encode(&secret)?;
            let secret_aead = self.vault.encrypt(private_key, &secret_blob)?;
            self.vault.add_secret(uuid, (meta_aead, secret_aead));
            Ok(uuid)
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Get a secret and it's meta data from the vault.
    pub fn read(&self, uuid: &Uuid) -> Result<Option<(SecretMeta, Secret)>> {
        if let Some(secret_meta) = self.get_secret_meta(uuid)? {
            if let Some(secret) = self.get_secret(uuid)? {
                Ok(Some((secret_meta, secret)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Update a secret in the vault.
    pub fn update(
        &mut self,
        uuid: Uuid,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<()> {
        /*
        let mut meta = self.meta()?;

        let existing_meta = meta.get_secret_meta(&uuid);

        if existing_meta.is_none() {
            return Err(Error::SecretDoesNotExist(uuid));
        }

        let existing_meta = existing_meta.unwrap();

        // Label has changed, so ensure uniqueness
        if existing_meta.label() != secret_meta.label() {
            if meta.find_by_label(secret_meta.label()).is_some() {
                return Err(Error::SecretAlreadyExists(
                    secret_meta.label().to_string(),
                ));
            }
        }

        meta.add_secret_meta(uuid, secret_meta);
        self.set_meta(meta)?;
        */

        if let Some(private_key) = &self.private_key {
            let meta_blob = encode(&secret_meta)?;
            let meta_aead = self.vault.encrypt(private_key, &meta_blob)?;

            let secret_blob = encode(&secret)?;
            let secret_aead = self.vault.encrypt(private_key, &secret_blob)?;
            self.vault.add_secret(uuid, (meta_aead, secret_aead));
            Ok(())
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Delete a secret and it's meta data from the vault.
    pub fn delete(&mut self, uuid: &Uuid) -> Result<()> {
        self.vault.remove_secret(uuid);
        Ok(())
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
            self.private_key = Some(Box::new(private_key));
            self.meta()
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
        let meta = keeper.meta()?;

        assert_eq!(&label, meta.label());

        let secret_label = String::from("Mock Secret");
        let secret_value = String::from("Super Secret Note");
        let secret = Secret::Text(secret_value.clone());
        let secret_meta = SecretMeta::new(secret_label, secret.kind());

        let secret_uuid = keeper.create(secret_meta.clone(), secret.clone())?;

        let saved_secret = keeper.get_secret(&secret_uuid)?.unwrap();
        assert_eq!(secret, saved_secret);

        let saved_secret_meta = keeper.get_secret_meta(&secret_uuid)?.unwrap();
        assert_eq!(secret_meta, saved_secret_meta);

        keeper.lock();

        Ok(())
    }
}
