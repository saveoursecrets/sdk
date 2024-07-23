use crate::vault::secret::SecretId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

mod export;
mod import;

pub use export::export_authenticator;
pub use import::import_authenticator;

const OTP_AUTH_URLS: &str = "otp_auth.json";

/// URLs for an authenticator folder.
#[derive(Default, Serialize, Deserialize)]
pub struct AuthenticatorUrls {
    /// Collection of `otpauth:` URLs.
    pub otp: HashMap<SecretId, Url>,
}
