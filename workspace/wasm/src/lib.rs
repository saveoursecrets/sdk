//! Webassembly bindings to the vault and gatekeeper.
use wasm_bindgen::prelude::*;

use sos_core::{
    gatekeeper::Gatekeeper,
    vault::Vault
};

/// Binding to the gatekeeper functionality.
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
        new_vault(vault)
    }
}

/// Load a vault from a buffer.
#[wasm_bindgen]
pub fn load_vault(buffer: Vec<u8>) -> Result<WebVault, JsError> {
    let vault = Vault::read_buffer(buffer)?;
    Ok(new_vault(vault))
}

/// Factory for creating a new web vault.
pub fn new_vault(vault: Vault) -> WebVault {
    let keeper = Gatekeeper::new(vault);
    WebVault {
        keeper, 
    }
}
