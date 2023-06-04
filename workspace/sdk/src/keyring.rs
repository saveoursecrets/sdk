use crate::vault::secret::SecretId;
use keyring::{Entry, Result};
use once_cell::sync::Lazy;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::Mutex;
use urn::Urn;

#[allow(dead_code)]
const SERVICE_NAME: &str = "com.saveoursecrets";
#[allow(dead_code)]
const URN_PREFIX: &str = "urn:sos";
static KEYRING: Lazy<Arc<Mutex<NativeKeyring>>> =
    Lazy::new(|| Arc::new(Mutex::new(Default::default())));

/// Get the native keyring mirror.
pub fn get_native_keyring() -> Arc<Mutex<NativeKeyring>> {
    Arc::clone(&KEYRING)
}

/// Native keyring provides access to the system keychain.
#[derive(Default)]
pub struct NativeKeyring {
    enabled: bool,
}

impl NativeKeyring {
    /// Determine if this native keyring mirror is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set if this native keyring mirror is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn service_name(&self,
        secret_id: &SecretId,
    ) -> String {
        format!("{}:{}:{}", URN_PREFIX, SERVICE_NAME, secret_id)
    }

    fn entry_name(
        &self,
        secret_name: &str,
    ) -> String {
        secret_name.to_owned()
    }

    /// Set a password in the native keyring.
    #[allow(dead_code)]
    pub(crate) fn set_entry(
        &self,
        secret_id: &SecretId,
        secret_name: &str,
        password: &SecretString,
    ) -> Result<()> {
        if self.enabled {
            let service = self.service_name(secret_id);
            let entry_name = self.entry_name(secret_name);
            let entry = Entry::new(&service, &entry_name)?;
            entry.set_password(password.expose_secret())?;
        }
        Ok(())
    }

    /// Delete a password in the native keyring.
    #[allow(dead_code)]
    pub(crate) fn delete_entry(
        &self,
        secret_id: &SecretId,
        secret_name: &str,
    ) -> Result<()> {
        if self.enabled {
            let service = self.service_name(secret_id);
            let entry_name = self.entry_name(secret_name);
            let entry = Entry::new(&service, &entry_name)?;
            entry.delete_password()?;
        }
        Ok(())
    }
}
