//! Gatekeeper manages access to a vault.
//!
//! It stores the passphrase in memory so should only be used on client
//! implementations.
use crate::{
    crypto::aes_gcm_256, from_encoded_buffer, into_encoded_buffer, secret::{MetaData, Secret}, vault::Vault,
};
use anyhow::{bail, Result};
use uuid::Uuid;
use zeroize::Zeroize;

/// Manage access to a vault's secrets.
#[derive(Default)]
pub struct Gatekeeper {
    /// The master passphrase.
    passphrase: Option<Box<[u8; 32]>>,
    /// The underlying vault.
    vault: Vault,
}

impl Gatekeeper {
    /// Create a new gatekeeper.
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            passphrase: None,
        }
    }

    /// Attempt to decrypt the index meta data for the vault
    /// using the passphrase assigned to this gatekeeper.
    pub fn meta(&self) -> Result<MetaData> {
        if let Some(passphrase) = &self.passphrase {
            if let Some(meta_aead) = self.vault.index().meta() {
                let meta_blob = aes_gcm_256::decrypt(passphrase, meta_aead)?;
                let meta_data: MetaData = from_encoded_buffer(meta_blob)?;
                Ok(meta_data)
            } else {
                bail!("vault meta data uninitialized")
            }
        } else {
            bail!("vault is not unlocked")
        }
    }

    /// Set the meta data for the vault.
    pub fn set_meta(&mut self, meta_data: MetaData) -> Result<()> {
        if let Some(passphrase) = &self.passphrase {
            let meta_blob = into_encoded_buffer(&meta_data)?;
            let meta_aead = aes_gcm_256::encrypt(passphrase, &meta_blob)?;
            self.vault.index_mut().set_meta(Some(meta_aead));
            Ok(())
        } else {
            bail!("vault is not unlocked")
        }
    }

    /// Add a secret to the vault.
    pub fn add_secret(&mut self, label: String, secret: &Secret) -> Result<Uuid> {
        if let Some(passphrase) = &self.passphrase {
            let uuid = Uuid::new_v4();
            let mut meta = self.meta()?;
            meta.add_reference(uuid.clone(), label);

            let secret_blob = into_encoded_buffer(secret)?;
            let secret_aead = aes_gcm_256::encrypt(passphrase, &secret_blob)?;
            self.vault.add_secret(uuid, secret_aead);
            self.set_meta(meta)?;
            Ok(uuid)
        } else {
            bail!("vault is not unlocked")
        }
    }

    /// Get a secret from the vault.
    pub fn get_secret(&mut self, uuid: &Uuid) -> Result<Secret> {
        if let Some(passphrase) = &self.passphrase {
            if let Some(secret_aead) = self.vault.get_secret(uuid) {
                let secret_blob = aes_gcm_256::decrypt(passphrase, secret_aead)?;
                let secret: Secret = from_encoded_buffer(secret_blob)?;
                Ok(secret)
            } else {
                bail!("secret does not exist")
            }
        } else {
            bail!("vault is not unlocked")
        }
    }

    /// Unlock the vault by setting the decryption passphrase.
    pub fn unlock(&mut self, passphrase: [u8; 32]) {
        self.passphrase = Some(Box::new(passphrase));
    }

    /// Lock the vault by deleting the stored passphrase
    /// associated with the vault, securely zeroing the
    /// underlying memory.
    pub fn lock(&mut self) {
        if let Some(passphrase) = self.passphrase.as_mut() {
            passphrase.zeroize();
        }
        self.passphrase = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secret::{MetaData, Secret}, vault::Vault};
    use anyhow::Result;
    use rand::Rng;

    #[test]
    fn gatekeeper_secret_note() -> Result<()> {
        let passphrase: [u8; 32] = rand::thread_rng().gen();
        let vault: Vault = Default::default();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(passphrase);

        // No meta data has been initialized so we
        // have no way to decrypt the index.
        assert!(keeper.meta().is_err());

        let label = String::from("Mock Vault Label");

        let mut init_meta_data: MetaData = Default::default();
        init_meta_data.set_label(label.clone());
        keeper.set_meta(init_meta_data)?;

        // Decrypt the initialized meta data.
        let meta = keeper.meta()?;

        assert_eq!(&label, meta.label());

        let secret_label = String::from("Mock Secret");
        let secret_value = String::from("Super Secret Note");
        let secret = Secret::Text(secret_value.clone());

        let secret_uuid = keeper.add_secret(secret_label, &secret)?;

        let saved_secret = keeper.get_secret(&secret_uuid)?;
        assert_eq!(secret, saved_secret);

        keeper.lock();

        Ok(())
    }
}
