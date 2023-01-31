//! Conversion types for various CSV formats.

pub mod bitwarden;
pub mod chrome;
pub mod dashlane;
pub mod firefox;
pub mod macos;
pub mod one_password;

use parking_lot::RwLock;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use url::Url;

use sos_core::{
    search::SearchIndex,
    secret::{IdentificationKind, Secret, SecretMeta},
    vault::Vault,
    Gatekeeper, Timestamp,
};

use crate::Convert;

/// Default label for CSV records when a title is not available.
pub const UNTITLED: &str = "Untitled";

/// Generic CSV entry type.
pub enum GenericCsvEntry {
    /// Password Entry.
    Password(GenericPasswordRecord),
    /// Note Entry.
    Note(GenericNoteRecord),
    /// Identification Entry.
    Id(GenericIdRecord),
}

impl GenericCsvEntry {
    /// Get the label for the record.
    fn label(&self) -> &str {
        match self {
            Self::Password(record) => &record.label,
            Self::Note(record) => &record.label,
            Self::Id(record) => &record.label,
        }
    }

    fn tags(&mut self) -> &mut Option<HashSet<String>> {
        match self {
            Self::Password(record) => &mut record.tags,
            Self::Note(record) => &mut record.tags,
            Self::Id(record) => &mut record.tags,
        }
    }
}

impl From<GenericCsvEntry> for Secret {
    fn from(value: GenericCsvEntry) -> Self {
        match value {
            GenericCsvEntry::Password(record) => Secret::Account {
                account: record.username,
                password: SecretString::new(record.password),
                url: record.url,
                user_data: Default::default(),
            },
            GenericCsvEntry::Note(record) => Secret::Note {
                text: SecretString::new(record.text),
                user_data: Default::default(),
            },
            GenericCsvEntry::Id(record) => Secret::Identification {
                id_kind: record.id_kind,
                number: SecretString::new(record.number),
                issue_place: record.issue_place,
                issue_date: record.issue_date,
                expiration_date: record.expiration_date,
                user_data: Default::default(),
            },
        }
    }
}

/// Generic password record.
pub struct GenericPasswordRecord {
    /// The label of the entry.
    pub label: String,
    /// The URL of the entry.
    pub url: Option<Url>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// OTP auth information for the entry.
    pub otp_auth: Option<String>,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
    // TODO: support notes for 1Password/Bitwarden etc.
}

/// Generic note record.
pub struct GenericNoteRecord {
    /// The label of the entry.
    pub label: String,
    /// The text for the note entry.
    pub text: String,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
}

/// Generic identification record.
pub struct GenericIdRecord {
    /// The label of the entry.
    pub label: String,
    /// The kind of identification.
    pub id_kind: IdentificationKind,
    /// The number for the entry.
    pub number: String,
    /// The issue place for the entry.
    pub issue_place: Option<String>,
    /// The issue date for the entry.
    pub issue_date: Option<Timestamp>,
    /// The expiration date for the entry.
    pub expiration_date: Option<Timestamp>,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
}

/// Convert from generic password records.
pub struct GenericCsvConvert;

impl Convert for GenericCsvConvert {
    type Input = Vec<GenericCsvEntry>;

    fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));

        keeper.unlock(password.expose_secret())?;

        let mut duplicates: HashMap<String, usize> = HashMap::new();

        for mut entry in source {
            // Handle duplicate labels by incrementing a counter
            let mut label = entry.label().to_owned();
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

            let tags = entry.tags().take();
            let secret: Secret = entry.into();
            let mut meta = SecretMeta::new(label, secret.kind());
            if let Some(tags) = tags {
                meta.set_tags(tags);
            }
            keeper.create(meta, secret)?;
        }

        keeper.lock();
        Ok(keeper.take())
    }
}
