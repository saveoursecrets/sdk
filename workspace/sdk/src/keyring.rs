use crate::vault::secret::SecretId;
use keyring::{Entry, Result};
use once_cell::sync::Lazy;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

#[allow(dead_code)]
const SERVICE_NAME: &str = "https://saveoursecrets.com";
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

    fn service_name(
        &self,
        secret_id: &SecretId,
        website: Option<&Url>,
    ) -> String {
        let service = if let Some(url) = website {
            url.to_string()
        } else {
            SERVICE_NAME.to_owned()
        };
        format!("{}:{}:{}", URN_PREFIX, secret_id, service)
    }

    fn entry_name(&self, secret_name: &str, username: &str) -> String {
        format!("{} ({})", secret_name, username)
    }

    /// Create a password in the native keyring.
    #[allow(dead_code)]
    pub(crate) fn create_entry(
        &self,
        secret_id: &SecretId,
        secret_name: &str,
        username: &str,
        password: &SecretString,
        website: Option<&Url>,
    ) -> Result<()> {
        if self.enabled {
            let service = self.service_name(secret_id, website);
            let entry_name = self.entry_name(secret_name, username);
            let entry = Entry::new(&service, &entry_name)?;
            entry.set_password(password.expose_secret())?;
        }
        Ok(())
    }

    /*
    /// Get a password in the native keyring.
    #[allow(dead_code)]
    pub(crate) fn get_entry(
        &self,
        secret_id: &SecretId,
        secret_name: &str,
        username: &str,
        website: Option<&Url>,
    ) -> Result<Option<SecretString>> {
        if self.enabled {
            let service = self.service_name(secret_id, website);
            let entry_name = self.entry_name(secret_name, username);
            let entry = Entry::new(&service, &entry_name)?;
            match entry.get_password() {
                Ok(password) => Ok(Some(SecretString::new(password))),
                Err(e) => match e {
                    Error::NoEntry => Ok(None),
                    _ => Err(e),
                }
            }
        } else {
            Ok(None)
        }
    }
    */

    /// Delete a password in the native keyring.
    #[allow(dead_code)]
    pub(crate) fn delete_entry(
        &self,
        secret_id: &SecretId,
        secret_name: &str,
        username: &str,
        website: Option<&Url>,
    ) -> Result<()> {
        if self.enabled {
            let service = self.service_name(secret_id, website);
            let entry_name = self.entry_name(secret_name, username);
            let entry = Entry::new(&service, &entry_name)?;
            entry.delete_password()?;
        }
        Ok(())
    }
}
