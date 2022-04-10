#![deny(missing_docs)]
#![allow(clippy::new_without_default)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    decode, encode,
    gatekeeper::Gatekeeper,
    secret::{MetaData, Secret, SecretMeta},
    uuid::Uuid,
    vault::Vault,
};

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[doc(hidden)]
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[doc(hidden)]
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    console_log!("WASM: module started {:?}", std::thread::current().id());
}

/// Binding to the gatekeeper for a vault.
#[wasm_bindgen]
pub struct WebVault {
    keeper: Gatekeeper,
}

/// Request used to create or update a secret.
#[derive(Serialize, Deserialize)]
pub struct SecretData {
    #[serde(rename = "secretId")]
    secret_id: Option<Uuid>,
    meta: SecretMeta,
    secret: Secret,
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

    /// Initialize the vault with the given name, label and password.
    pub fn initialize(
        &mut self,
        name: JsValue,
        label: JsValue,
        password: JsValue,
    ) -> Result<(), JsError> {
        let name: String = name.into_serde()?;
        let label: String = label.into_serde()?;
        let password: String = password.into_serde()?;
        self.keeper.initialize(name, label, password)?;
        Ok(())
    }

    /// Import a buffer as the vault.
    #[wasm_bindgen(js_name = "importBuffer")]
    pub fn import_buffer(&mut self, buffer: JsValue) -> Result<(), JsError> {
        let buffer: Vec<u8> = buffer.into_serde()?;
        let vault: Vault = decode(buffer)?;
        self.keeper.set_vault(vault);
        Ok(())
    }

    /// Get the meta data for the vault.
    #[wasm_bindgen(js_name = "getMetaData")]
    pub fn get_meta_data(&self) -> Result<JsValue, JsError> {
        let meta = self.keeper.meta()?;
        let sorted_meta = self.sort_meta_data(&meta);
        Ok(JsValue::from_serde(&sorted_meta)?)
    }

    fn sort_meta_data<'a>(
        &self,
        meta: &'a MetaData,
    ) -> BTreeMap<String, (&'a Uuid, &'a SecretMeta)> {
        meta.secrets()
            .iter()
            .map(|(k, v)| {
                let key =
                    format!("{} {}", v.label().to_lowercase().to_string(), k);
                (key, (k, v))
            })
            .collect()
    }

    /// Get the identifier for the vault.
    pub fn id(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(self.keeper.id())?)
    }

    /// Get the public name for the vault.
    pub fn name(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(self.keeper.name())?)
    }

    /// Get the private label for the vault.
    pub fn label(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(&self.keeper.label()?)?)
    }

    /// Create a new secret.
    pub fn create(&mut self, request: JsValue) -> Result<JsValue, JsError> {
        let mut data: SecretData = request.into_serde()?;

        if let Secret::Blob {
            ref mut mime,
            ref name,
            ..
        } = data.secret
        {
            if let Some(name) = name {
                if let Some(mime_type) =
                    mime_guess::from_path(name).first().map(|m| m.to_string())
                {
                    *mime = Some(mime_type);
                }
            }
        }

        let uuid = self.keeper.create(data.meta, data.secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

    /// Get a secret from the vault.
    pub fn read(&self, uuid: JsValue) -> Result<JsValue, JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let result = self.keeper.read(&uuid)?;
        Ok(JsValue::from_serde(&result)?)
    }

    /// Update a new secret.
    pub fn update(&mut self, request: JsValue) -> Result<(), JsError> {
        let mut data: SecretData = request.into_serde()?;

        let uuid = data.secret_id.as_ref().ok_or_else(|| {
            JsError::new("update requires a valid identifier")
        })?;

        if let Secret::Blob {
            ref mut mime,
            ref name,
            ..
        } = data.secret
        {
            if mime.is_none() {
                if let Some(name) = name {
                    if let Some(mime_type) = mime_guess::from_path(name)
                        .first()
                        .map(|m| m.to_string())
                    {
                        *mime = Some(mime_type);
                    }
                }
            }
        }

        console_log!("Updating secret");

        self.keeper.update(*uuid, data.meta, data.secret)?;

        console_log!("Secret update completed!");

        Ok(())
    }

    /// Delete a secret from the vault.
    pub fn delete(&mut self, uuid: JsValue) -> Result<JsValue, JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let result = self.keeper.delete(&uuid)?;
        Ok(JsValue::from_serde(&result)?)
    }

    /*
    /// Create a new file upload.
    #[wasm_bindgen(js_name = "createFileUpload")]
    #[deprecated]
    pub fn create_file_upload(
        &mut self,
        request: JsValue,
    ) -> Result<JsValue, JsError> {
        let FileUpload {
            label,
            buffer,
            name,
        } = request.into_serde()?;

        let mime = mime_guess::from_path(name).first().map(|m| m.to_string());
        let secret = Secret::Blob { buffer, mime, name: None };
        let meta_data = SecretMeta::new(label, secret.kind());
        let uuid = self.keeper.add(meta_data, secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }
    */

    /*
    /// Set a secret for this vault.
    pub fn set_secret(
        &mut self,
        secret: JsValue,
        uuid: JsValue,
    ) -> Result<JsValue, JsError> {
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
    pub fn set_secret_meta(
        &mut self,
        uuid: JsValue,
        meta_data: JsValue,
    ) -> Result<(), JsError> {
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
    */

    /// Unlock the vault.
    pub fn unlock(&mut self, passphrase: JsValue) -> Result<JsValue, JsError> {
        let passphrase: String = passphrase.into_serde()?;
        let meta = self.keeper.unlock(passphrase)?;
        let sorted_meta = self.sort_meta_data(&meta);
        Ok(JsValue::from_serde(&sorted_meta)?)
    }

    /// Lock the vault.
    pub fn lock(&mut self) {
        self.keeper.lock();
    }

    /// Get a buffer of the encoded vault.
    pub fn buffer(&self) -> Result<Vec<u8>, JsError> {
        Ok(encode(self.keeper.vault())?)
    }
}

/// Generate a passphrase using the diceware module.
#[wasm_bindgen(js_name = "generatePassphrase")]
pub fn generate_passphrase(words: u8) -> Result<JsValue, JsError> {
    use sos_core::diceware::generate_passphrase_words;
    let (passphrase, bits) = generate_passphrase_words(words)?;
    Ok(JsValue::from_serde(&(passphrase, bits))?)
}
