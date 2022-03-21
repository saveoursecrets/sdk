#![deny(missing_docs)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta},
    uuid::Uuid,
    vault::Vault,
};

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
        let vault: Vault = Default::default();
        Self {
            keeper: Gatekeeper::new(vault),
        }
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
}

/// Load a vault from a buffer.
#[wasm_bindgen]
pub fn load_vault(buffer: Vec<u8>) -> Result<WebVault, JsError> {
    let vault = Vault::read_buffer(buffer)?;
    Ok(WebVault {
        keeper: Gatekeeper::new(vault),
    })
}
