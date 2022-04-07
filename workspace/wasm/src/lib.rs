#![deny(missing_docs)]
#![allow(clippy::new_without_default)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    decode, encode,
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta, MetaData},
    uuid::Uuid,
    vault::Vault,
};

use serde::{Deserialize, Serialize};
use url::Url;

use std::collections::{HashMap, BTreeMap};

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

/// Request used to create a new account password.
#[derive(Serialize, Deserialize)]
pub struct AccountPassword {
    label: String,
    account: String,
    url: String,
    password: String,
}

/// Request used to create a new secure note.
#[derive(Serialize, Deserialize)]
pub struct SecureNote {
    label: String,
    note: String,
}

/// Request used to create a new credentials list.
#[derive(Serialize, Deserialize)]
pub struct Credentials {
    label: String,
    credentials: HashMap<String, String>,
}

/// Request used to create a new file upload.
#[derive(Serialize, Deserialize)]
pub struct FileUpload {
    label: String,
    buffer: Vec<u8>,
    name: String,
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

    /// Initialize the vault with the given label and password.
    pub fn initialize(
        &mut self,
        label: JsValue,
        password: JsValue,
    ) -> Result<(), JsError> {
        let label: String = label.into_serde()?;
        let password: String = password.into_serde()?;
        self.keeper.initialize(label, password)?;
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

    fn sort_meta_data<'a>(&self, meta: &'a MetaData) -> BTreeMap<String, (&'a Uuid, &'a SecretMeta)> {
        meta.secrets()
            .iter()
            .map(|(k, v)| {
                (v.label().to_string(), (k, v))
            })
            .collect()
    }

    /// Get the identifier for the vault.
    pub fn id(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(self.keeper.id())?)
    }

    /// Get the label for the vault.
    pub fn label(&self) -> Result<JsValue, JsError> {
        Ok(JsValue::from_serde(&self.keeper.label()?)?)
    }

    /// Create a new account password.
    #[wasm_bindgen(js_name = "createAccountPassword")]
    pub fn create_account_password(
        &mut self,
        request: JsValue,
    ) -> Result<JsValue, JsError> {
        let AccountPassword {
            label,
            account,
            url,
            password,
        } = request.into_serde()?;

        let url = if url.is_empty() {
            None
        } else {
            let url: Url = url.parse()?;
            Some(url)
        };

        let secret = Secret::Account {
            account,
            url,
            password,
        };
        let meta_data = SecretMeta::new(label, secret.kind());
        let uuid = self.keeper.add(meta_data, secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

    /// Create a new secure note.
    #[wasm_bindgen(js_name = "createNote")]
    pub fn create_note(
        &mut self,
        request: JsValue,
    ) -> Result<JsValue, JsError> {
        let SecureNote { label, note } = request.into_serde()?;

        let secret = Secret::Text(note);
        let meta_data = SecretMeta::new(label, secret.kind());
        let uuid = self.keeper.add(meta_data, secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

    /// Create a new credentials list.
    #[wasm_bindgen(js_name = "createCredentials")]
    pub fn create_credentials(
        &mut self,
        request: JsValue,
    ) -> Result<JsValue, JsError> {
        let Credentials { label, credentials } = request.into_serde()?;

        let secret = Secret::Credentials(credentials);
        let meta_data = SecretMeta::new(label, secret.kind());
        let uuid = self.keeper.add(meta_data, secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

    /// Create a new file upload.
    #[wasm_bindgen(js_name = "createFileUpload")]
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
        let secret = Secret::Blob { buffer, mime };
        let meta_data = SecretMeta::new(label, secret.kind());
        let uuid = self.keeper.add(meta_data, secret)?;
        Ok(JsValue::from_serde(&uuid)?)
    }

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
