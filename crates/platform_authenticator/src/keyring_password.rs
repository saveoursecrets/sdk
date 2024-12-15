//! Interface to the platform keyring.

/// Service name used to store keyring passwords.
pub const SERVICE_NAME: &str = "com.saveoursecrets";

// MacOS implementation uses the security framework
// directly instead of the `keyring` crate.
#[cfg(target_os = "macos")]
mod macos {
    use super::SERVICE_NAME;
    use crate::{Error, Result};
    use secrecy::{ExposeSecret, SecretString};
    use security_framework::{
        passwords::{
            get_generic_password, set_generic_password,
            set_generic_password_options,
        },
        passwords_options::PasswordOptions,
    };

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    /// Find the password for an account.
    pub fn find_account_password(account_id: &str) -> Result<String> {
        match get_generic_password(SERVICE_NAME, account_id) {
            Ok(bytes) => Ok(std::str::from_utf8(&bytes)?.to_owned()),
            Err(e) => {
                let code = e.code();
                if code == ERR_SEC_ITEM_NOT_FOUND {
                    Err(Error::NoKeyringEntry)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Save the password for an account in the platform keyring.
    pub fn save_account_password(
        account_id: &str,
        password: SecretString,
    ) -> Result<()> {
        if let Some(access_group) = option_env!("SOS_ACCESS_GROUP") {
            let mut options = PasswordOptions::new_generic_password(
                SERVICE_NAME,
                account_id,
            );

            options.set_access_group(access_group);

            set_generic_password_options(
                password.expose_secret().as_bytes(),
                options,
            )?;
        } else {
            set_generic_password(
                SERVICE_NAME,
                account_id,
                password.expose_secret().as_bytes(),
            )?;
        }

        Ok(())
    }

    /// Whether platform keyring storage is supported.
    pub fn supported() -> bool {
        true
    }
}

// Other platforms use the `keyring` crate.
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
mod platform_keyring {
    use super::SERVICE_NAME;
    use crate::{Error, Result};
    use keyring::{Entry, Error as KeyringError};
    use secrecy::{ExposeSecret, SecretString};

    /// Find the password for an account.
    pub fn find_account_password(account_id: &str) -> Result<String> {
        let entry = Entry::new(SERVICE_NAME, account_id)?;
        match entry.get_password() {
            Ok(password) => Ok(password),
            Err(e) => match e {
                KeyringError::NoEntry => Err(Error::NoKeyringEntry),
                _ => Err(e.into()),
            },
        }
    }

    /// Save the password for an account in the platform keyring.
    pub fn save_account_password(
        account_id: &str,
        password: SecretString,
    ) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, account_id)?;
        entry.set_password(password.expose_secret())?;
        Ok(())
    }

    /// Whether platform keyring storage is supported.
    pub fn supported() -> bool {
        true
    }
}

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
pub use platform_keyring::*;

// Android is not currently supported.
// SEE: https://github.com/hwchen/keyring-rs/issues/127
#[cfg(target_os = "android")]
mod unsupported {
    use crate::Result;

    /// Find the password for an account.
    pub fn find_account_password(account_id: &str) -> Result<String> {
        unimplemented!();
    }

    /// Whether platform keyring storage is supported.
    pub fn supported() -> bool {
        false
    }
}

#[cfg(target_os = "android")]
pub use unsupported::*;
