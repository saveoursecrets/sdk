#![deny(missing_docs)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    gatekeeper::Gatekeeper,
    into_encoded_buffer,
    secret::{Secret, SecretMeta},
    uuid::Uuid,
};

use std::collections::HashMap;

/// Binding to the gatekeeper for a vault.
#[wasm_bindgen]
pub struct WebVault {
    keeper: Gatekeeper,
    index: HashMap<Uuid, SecretMeta>,
}

#[wasm_bindgen]
impl WebVault {
    /// Create an empty vault.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            keeper: Gatekeeper::new(Default::default()),
            index: Default::default(),
        }
    }

    /// Initialize the vault with the given label and password.
    pub fn initialize(&mut self, label: JsValue, password: JsValue) -> Result<(), JsError> {
        let label: String = label.into_serde()?;
        let password: String = password.into_serde()?;
        self.keeper.initialize(label, password)?;
        Ok(())
    }

    /// Get the index of the meta data for the collection of secrets.
    #[wasm_bindgen(js_name = "getSecretIndex")]
    pub fn get_secret_index(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(&self.index)?)
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
        Ok(into_encoded_buffer(self.keeper.vault())?)
    }
}
