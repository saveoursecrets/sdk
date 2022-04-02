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
    crypto::{
        aes_gcm_256,
        passphrase::{generate_secret_key, parse_salt},
    },
    from_encoded_buffer, into_encoded_buffer,
    secret::{MetaData, Secret, SecretMeta},
    vault::Vault,
    Error, Result,
};
use uuid::Uuid;
use zeroize::Zeroize;

/// Manage access to a vault's secrets.
#[derive(Default)]
pub struct Gatekeeper {
    /// The private key.
    private_key: Option<Box<[u8; 32]>>,
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

    /// Initialize the vault with the given label and password.
    pub fn initialize<S: AsRef<str>>(
        &mut self,
        label: String,
        password: S,
    ) -> Result<()> {
        // Initialize the private key and store the salt
        let private_key = self.vault.initialize(password.as_ref())?;
        self.private_key = Some(Box::new(private_key));

        // Assign the label to the meta data
        let mut init_meta_data: MetaData = Default::default();
        init_meta_data.set_label(label);
        self.set_meta(init_meta_data)?;
        Ok(())
    }

    /// Attempt to decrypt the index meta data and extract the label.
    pub fn label(&self) -> Result<String> {
        if let Some(private_key) = &self.private_key {
            if let Some(meta_aead) = self.vault.index().meta() {
                let meta_blob = aes_gcm_256::decrypt(private_key, meta_aead)?;
                let meta_data: MetaData = from_encoded_buffer(meta_blob)?;
                Ok(meta_data.label().to_string())
            } else {
                Err(Error::VaultNotInit)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Attempt to decrypt the index meta data for the vault
    /// using the passphrase assigned to this gatekeeper.
    pub fn meta(&self) -> Result<MetaData> {
        if let Some(private_key) = &self.private_key {
            if let Some(meta_aead) = self.vault.index().meta() {
                let meta_blob = aes_gcm_256::decrypt(private_key, meta_aead)?;
                let meta_data: MetaData = from_encoded_buffer(meta_blob)?;
                Ok(meta_data)
            } else {
                Err(Error::VaultNotInit)
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Set the meta data for the vault.
    pub fn set_meta(&mut self, meta_data: MetaData) -> Result<()> {
        if let Some(private_key) = &self.private_key {
            let meta_blob = into_encoded_buffer(&meta_data)?;
            let meta_aead = aes_gcm_256::encrypt(private_key, &meta_blob)?;
            self.vault.index_mut().set_meta(Some(meta_aead));
            Ok(())
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Set the meta data for a secret.
    pub fn set_secret_meta(
        &mut self,
        uuid: Uuid,
        meta_data: SecretMeta,
    ) -> Result<()> {
        let mut meta = self.meta()?;
        meta.add_secret_meta(uuid, meta_data);
        self.set_meta(meta)?;
        Ok(())
    }

    /// Get the meta data for a secret.
    pub fn get_secret_meta(&self, uuid: &Uuid) -> Result<SecretMeta> {
        let meta = self.meta()?;
        if let Some(meta_data) = meta.get_secret_meta(uuid) {
            Ok(meta_data.clone())
        } else {
            Err(Error::SecretMetaDoesNotExist(*uuid))
        }
    }

    /// Create or update a secret.
    pub fn set_secret(
        &mut self,
        secret: &Secret,
        uuid: Option<Uuid>,
    ) -> Result<Uuid> {
        if let Some(private_key) = &self.private_key {
            let uuid = uuid.unwrap_or_else(Uuid::new_v4);
            let secret_blob = into_encoded_buffer(secret)?;
            let secret_aead = aes_gcm_256::encrypt(private_key, &secret_blob)?;
            self.vault.add_secret(uuid, secret_aead);
            Ok(uuid)
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Get a secret from the vault.
    pub fn get_secret(&self, uuid: &Uuid) -> Result<Secret> {
        if let Some(private_key) = &self.private_key {
            if let Some(secret_aead) = self.vault.get_secret(uuid) {
                let secret_blob =
                    aes_gcm_256::decrypt(private_key, secret_aead)?;
                let secret: Secret = from_encoded_buffer(secret_blob)?;
                Ok(secret)
            } else {
                Err(Error::SecretDoesNotExist(*uuid))
            }
        } else {
            Err(Error::VaultLocked)
        }
    }

    /// Unlock the vault by setting the private key from a passphrase.
    pub fn unlock<S: AsRef<str>>(&mut self, passphrase: S) -> Result<MetaData> {
        if let Some(salt) = self.vault.salt() {
            let salt = parse_salt(salt)?;
            let private_key = generate_secret_key(passphrase, &salt)?;
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
    use crate::{secret::Secret, vault::Vault};
    use anyhow::Result;

    #[test]
    fn gatekeeper_secret_note() -> Result<()> {
        let passphrase = "mock-passphrase";
        let vault: Vault = Default::default();
        let mut keeper = Gatekeeper::new(vault);

        let label = String::from("Mock Vault Label");
        keeper.initialize(label.clone(), passphrase)?;

        //// Decrypt the initialized meta data.
        let meta = keeper.meta()?;

        assert_eq!(&label, meta.label());

        let secret_label = String::from("Mock Secret");
        let secret_value = String::from("Super Secret Note");
        let secret = Secret::Text(secret_value.clone());

        let secret_uuid = keeper.set_secret(&secret, None)?;

        let secret_meta = SecretMeta::new(secret_label);
        keeper.set_secret_meta(secret_uuid.clone(), secret_meta.clone())?;

        let saved_secret = keeper.get_secret(&secret_uuid)?;
        assert_eq!(secret, saved_secret);

        let saved_secret_meta = keeper.get_secret_meta(&secret_uuid)?;
        assert_eq!(secret_meta, saved_secret_meta);

        keeper.lock();

        Ok(())
    }
}
