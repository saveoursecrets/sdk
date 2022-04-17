#![deny(missing_docs)]
#![allow(clippy::new_without_default)]
//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    crypto::generate_random_ecdsa_signing_key,
    decode, encode,
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta},
    uuid::Uuid,
    vault::Vault,
};

use serde::{Deserialize, Serialize};
use sos_core::{
    address::address_compressed, diceware::generate_passphrase_words,
};
use std::collections::BTreeMap;
use web3_keystore::{decrypt, encrypt, KeyStore};
use zeroize::Zeroize;

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

/// Request used to create or update a secret.
#[derive(Serialize, Deserialize)]
pub struct SecretData {
    #[serde(rename = "secretId")]
    secret_id: Option<Uuid>,
    meta: SecretMeta,
    secret: Secret,
}

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
    #[wasm_bindgen(js_name = "getVaultMeta")]
    pub fn get_meta_data(&self) -> Result<JsValue, JsError> {
        let _meta = self.keeper.meta()?;
        let sorted_meta = self.sort_meta_data()?;
        Ok(JsValue::from_serde(&sorted_meta)?)
    }

    fn sort_meta_data(
        &self,
    ) -> Result<BTreeMap<String, (Uuid, SecretMeta)>, JsError> {
        Ok(self
            .keeper
            .meta_data()?
            .into_iter()
            .map(|(k, v)| {
                let key = format!("{} {}", v.label().to_lowercase(), k);
                (key, (*k, v))
            })
            .collect())
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

        self.keeper.update(uuid, data.meta, data.secret)?;

        console_log!("Secret update completed!");

        Ok(())
    }

    /// Delete a secret from the vault.
    pub fn delete(&mut self, uuid: JsValue) -> Result<JsValue, JsError> {
        let uuid: Uuid = uuid.into_serde()?;
        let result = self.keeper.delete(&uuid)?;
        Ok(JsValue::from_serde(&result)?)
    }

    /// Unlock the vault.
    pub fn unlock(&mut self, passphrase: JsValue) -> Result<JsValue, JsError> {
        let passphrase: String = passphrase.into_serde()?;
        let _meta = self.keeper.unlock(passphrase)?;
        let sorted_meta = self.sort_meta_data()?;
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

/// Store the state for a new account signup.
#[wasm_bindgen]
pub struct Signup {
    /// Passphrase for the encrypted keystore.
    key_passphrase: Option<String>,
}

#[wasm_bindgen]
impl Signup {
    /// Create a signup for a new account.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            key_passphrase: None,
        }
    }

    /// Set the passphrase for the key generation.
    #[wasm_bindgen(js_name = "setPassphrase")]
    pub fn set_passphrase(
        &mut self,
        passphrase: JsValue,
    ) -> Result<JsValue, JsError> {
        let passphrase: String = passphrase.into_serde()?;
        self.key_passphrase = Some(passphrase);
        Ok(JsValue::null())
    }

    // TODO: verify private key passphrase matches stored value (memorization test)
    // TODO: verify encryption passphrase matches stored value (memorization test)
    // TODO: initialize a vault with the encryption passphrase
    // TODO: verify encryption passphrase can decrypt the vault meta data
    // TODO: send the vault to the remote server to complete account creation

    /// Verify the passphrase for a keystore by decrypting
    /// the private key.
    #[wasm_bindgen(js_name = "verifyPrivateKey")]
    pub fn verify_private_key(
        &mut self,
        passphrase: JsValue,
        keystore: JsValue,
    ) -> Result<JsValue, JsError> {
        let passphrase: String = passphrase.into_serde()?;
        let keystore: KeyStore = keystore.into_serde()?;
        let _ = decrypt(&keystore, &passphrase)?;
        Ok(JsValue::null())
    }

    /// Generate an ECDSA private key and protect it with the given passphrase.
    #[wasm_bindgen(js_name = "generatePrivateKey")]
    pub fn generate_private_key(&self) -> Result<JsValue, JsError> {
        let passphrase = self
            .key_passphrase
            .as_ref()
            .ok_or_else(|| JsError::new("passphrase has not been set"))?;
        let (private_key, public_key) = generate_random_ecdsa_signing_key();
        let address = address_compressed(&public_key)?;
        let mut rng = rand::thread_rng();
        let keystore =
            encrypt(&mut rng, &private_key, passphrase, Some(address.clone()))
                .expect("unable to encrypt private key store");
        Ok(JsValue::from_serde(&keystore)?)
    }

    /// Dispose of the internal state securely
    /// zeroing memory.
    pub fn dispose(&mut self) {
        if let Some(key_passphrase) = self.key_passphrase.as_mut() {
            key_passphrase.zeroize();
        }

        self.key_passphrase = None;
    }
}

/// Generate a passphrase using the diceware module.
#[wasm_bindgen(js_name = "generatePassphrase")]
pub fn generate_passphrase(words: u8) -> Result<JsValue, JsError> {
    let (passphrase, bits) = generate_passphrase_words(words)?;
    Ok(JsValue::from_serde(&(passphrase, bits))?)
}
