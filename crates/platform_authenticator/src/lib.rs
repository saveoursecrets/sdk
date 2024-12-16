//! Platform authenticator and keyring support for the
//! [Save Our Secrets SDK](https://saveoursecrets.com).
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
use secrecy::SecretString;

mod error;

pub mod keyring_password;
pub mod local_auth;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

/// Attempt to find authentication credentials for an account.
///
/// First verify user presence via the platform
/// authenticator and then attempt to retrieve the account
/// password from the platform keyring.
pub async fn find_account_credential(
    account_id: &str,
) -> Result<SecretString> {
    if local_auth::supported() {
        if local_auth::authenticate(Default::default()) {
            if keyring_password::supported() {
                match keyring_password::find_account_password(account_id) {
                    Ok(password) => Ok(SecretString::new(password.into())),
                    Err(e) => Err(e),
                }
            } else {
                Err(Error::Unauthorized)
            }
        } else {
            Err(Error::Forbidden)
        }
    } else {
        Err(Error::Unauthorized)
    }
}
