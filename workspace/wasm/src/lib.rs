#![deny(missing_docs)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    into_encoded_buffer,
    gatekeeper::Gatekeeper,
    secret::{MetaData, Secret, SecretMeta},
    uuid::Uuid,
};

use sha3::{Keccak256, Digest};

/// Binding to the gatekeeper for a vault.
#[wasm_bindgen]
pub struct WebVault {
    keeper: Gatekeeper,
}

#[wasm_bindgen]
impl WebVault {
    /// Create an empty vault.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            keeper: Gatekeeper::new(Default::default()),
        }
    }

    /// Initialize the vault with the given label and passphrase.
    pub fn initialize(&mut self, label: JsValue, passphrase: JsValue) -> Result<(), JsError> {
        let label: String = label.into_serde()?;
        let passphrase: [u8; 32] = passphrase.into_serde()?;
        self.keeper.unlock(passphrase);

        let mut init_meta_data: MetaData = Default::default();
        init_meta_data.set_label(label);
        self.keeper.set_meta(init_meta_data)?;

        Ok(())
    }

    /// Get the identifier for the vault.
    pub fn id(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(self.keeper.id())?)
    }

    /// Get the label for the vault.
    pub fn label(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(&self.keeper.label()?)?)
    }

    /// Set a secret for this vault.
    pub fn set_secret(&mut self, secret: JsValue, uuid: JsValue) -> Result<JsValue, JsError> {
        let secret: Secret = secret.into_serde()?;
        let uuid: Option<Uuid> = uuid.into_serde()?;
        let uuid = self.keeper.set_secret(&secret, uuid)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

    /// Get a secret from the vault.
    pub fn get_secret(&self, uuid: JsValue) -> Result<JsValue, JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let secret = self.keeper.get_secret(&uuid)?;
        Ok(JsValue::from_serde(&secret)?)
    }

    /// Set the meta data for a secret.
    pub fn set_secret_meta(&mut self, uuid: JsValue, meta_data: JsValue) -> Result<(), JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let meta_data: SecretMeta = meta_data.into_serde()?;
        self.keeper.set_secret_meta(uuid, meta_data)?;
        Ok(())
    }

    /// Get the meta data for a secret.
    pub fn get_secret_meta(&self, uuid: JsValue) -> Result<JsValue, JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let meta_data = self.keeper.get_secret_meta(&uuid)?;
        Ok(JsValue::from_serde(&meta_data)?)
    }

    /// Unlock the vault.
    pub fn unlock(&mut self, passphrase: JsValue) -> Result<(), JsError> {
        let passphrase: [u8; 32] = passphrase.into_serde()?;
        self.keeper.unlock(passphrase);
        Ok(())
    }

    /// Lock the vault.
    pub fn lock(&mut self) {
        self.keeper.lock();
    }

    /// Get a buffer of the encoded vault.
    pub fn buffer(&self) -> Result<Vec<u8>, JsError> {
        let buffer = into_encoded_buffer(self.keeper.vault())?;
        Ok(buffer)
    }
}

/// Compute the keccak256 digest of a string.
#[wasm_bindgen]
pub fn keccak256(value: JsValue) -> Result<Vec<u8>, JsError> {
    let value: String = value.into_serde()?;
    Ok(Keccak256::digest(value).to_vec())
}
