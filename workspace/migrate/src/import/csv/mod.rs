//! Conversion types for various CSV formats.

pub mod chrome_passwords;
pub mod firefox_passwords;
pub mod macos_passwords;

use parking_lot::RwLock;
use secrecy::{ExposeSecret, SecretString};
use std::{collections::HashMap, sync::Arc};
use url::Url;

use sos_core::{
    search::SearchIndex,
    secret::{Secret, SecretMeta},
    vault::Vault,
    Gatekeeper,
};

use crate::Convert;

/// Generic password record.
pub struct GenericPasswordRecord {
    /// The label of the entry.
    pub label: String,
    /// The URL of the entry.
    pub url: Url,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// OTP auth information for the entry.
    pub otp_auth: Option<String>,
}

/// Convert from generic password records.
pub struct GenericCsvConvert;

impl Convert for GenericCsvConvert {
    type Input = Vec<GenericPasswordRecord>;

    fn convert(
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));

        keeper.unlock(password.expose_secret())?;

        let mut duplicates: HashMap<String, usize> = HashMap::new();

        for entry in source {
            // Handle duplicate labels by incrementing a counter
            let mut label = entry.label;
            let search = search_index.read();
            if search.find_by_label(keeper.vault().id(), &label).is_some() {
                duplicates
                    .entry(label.clone())
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
                let counter = duplicates.get(&label).unwrap();
                label = format!("{} {}", label, counter);
            }
            // Must drop before writing
            drop(search);

            let secret = Secret::Account {
                account: entry.username,
                password: SecretString::new(entry.password),
                url: Some(entry.url),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());
            keeper.create(meta, secret)?;
        }

        keeper.lock();
        Ok(keeper.take())
    }
}
