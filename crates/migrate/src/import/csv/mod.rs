//! Conversion types for various CSV formats.

pub mod bitwarden;
pub mod chrome;
pub mod dashlane;
pub mod firefox;
pub mod macos;
pub mod one_password;

use crate::{Convert, Error};
use async_trait::async_trait;
use sos_search::SearchIndex;
use sos_core::{crypto::AccessKey, UtcDateTime};
use sos_filesystem::FileSystemAccessPoint;
use sos_vault::{
    secret::{
        IdentityKind, Secret, SecretId, SecretMeta, SecretRow, UserData,
    },
    SecretAccess, Vault,
};
use std::collections::{HashMap, HashSet};
use url::Url;
use vcard4::Vcard;

/// Default label for CSV records when a title is not available.
pub const UNTITLED: &str = "Untitled";

/// Generic CSV entry type.
pub enum GenericCsvEntry {
    /// Password Eentry.
    Password(GenericPasswordRecord),
    /// Note entry.
    Note(GenericNoteRecord),
    /// Identity entry.
    Id(GenericIdRecord),
    /// Payment entry.
    Payment(GenericPaymentRecord),
    /// Contact entry.
    Contact(Box<GenericContactRecord>),
}

impl GenericCsvEntry {
    /// Get the label for the record.
    fn label(&self) -> &str {
        match self {
            Self::Password(record) => &record.label,
            Self::Note(record) => &record.label,
            Self::Id(record) => &record.label,
            Self::Payment(record) => record.label(),
            Self::Contact(record) => &record.label,
        }
    }

    /// Get the tags for the record.
    fn tags(&mut self) -> &mut Option<HashSet<String>> {
        match self {
            Self::Password(record) => &mut record.tags,
            Self::Note(record) => &mut record.tags,
            Self::Id(record) => &mut record.tags,
            Self::Payment(record) => record.tags(),
            Self::Contact(record) => &mut record.tags,
        }
    }

    /// Get the note for the record.
    fn note(&mut self) -> &mut Option<String> {
        match self {
            Self::Password(record) => &mut record.note,
            Self::Note(record) => &mut record.note,
            Self::Id(record) => &mut record.note,
            Self::Payment(record) => record.note(),
            Self::Contact(record) => &mut record.note,
        }
    }
}

impl From<GenericCsvEntry> for Secret {
    fn from(value: GenericCsvEntry) -> Self {
        match value {
            GenericCsvEntry::Password(record) => Secret::Account {
                account: record.username,
                password: record.password.into(),
                url: record.url,
                user_data: if let Some(notes) = record.note {
                    UserData::new_comment(notes)
                } else {
                    Default::default()
                },
            },
            GenericCsvEntry::Note(record) => Secret::Note {
                text: record.text.into(),
                user_data: if let Some(notes) = record.note {
                    UserData::new_comment(notes)
                } else {
                    Default::default()
                },
            },
            GenericCsvEntry::Id(record) => Secret::Identity {
                id_kind: record.id_kind,
                number: record.number.into(),
                issue_place: record.issue_place,
                issue_date: record.issue_date,
                expiry_date: record.expiration_date,
                user_data: if let Some(notes) = record.note {
                    UserData::new_comment(notes)
                } else {
                    Default::default()
                },
            },
            GenericCsvEntry::Payment(record) => match record {
                GenericPaymentRecord::Card {
                    number,
                    code,
                    expiration,
                    note,
                    ..
                } => {
                    // TODO: handle country?
                    Secret::Card {
                        number: number.into(),
                        cvv: code.into(),
                        expiry: expiration,
                        name: None,
                        atm_pin: None,
                        user_data: if let Some(notes) = note {
                            UserData::new_comment(notes)
                        } else {
                            Default::default()
                        },
                    }
                }
                GenericPaymentRecord::BankAccount {
                    account_number,
                    routing_number,
                    note,
                    ..
                } => {
                    // TODO: handle country and account_holder
                    Secret::Bank {
                        number: account_number.into(),
                        routing: routing_number.into(),
                        bic: None,
                        iban: None,
                        swift: None,
                        user_data: if let Some(notes) = note {
                            UserData::new_comment(notes)
                        } else {
                            Default::default()
                        },
                    }
                }
            },
            GenericCsvEntry::Contact(record) => Secret::Contact {
                vcard: Box::new(record.vcard),
                user_data: if let Some(notes) = record.note {
                    UserData::new_comment(notes)
                } else {
                    Default::default()
                },
            },
        }
    }
}

/// Generic password record.
pub struct GenericPasswordRecord {
    /// The label of the entry.
    pub label: String,
    /// The URLs of the entry.
    pub url: Vec<Url>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// OTP auth information for the entry.
    pub otp_auth: Option<String>,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
    /// Optional note.
    pub note: Option<String>,
}

/// Generic note record.
pub struct GenericNoteRecord {
    /// The label of the entry.
    pub label: String,
    /// The text for the note entry.
    pub text: String,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
    /// Optional note.
    pub note: Option<String>,
}

/// Generic contact record.
pub struct GenericContactRecord {
    /// The label of the entry.
    pub label: String,
    /// The vcard for the entry.
    pub vcard: Vcard,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
    /// Optional note.
    pub note: Option<String>,
}

/// Generic identification record.
pub struct GenericIdRecord {
    /// The label of the entry.
    pub label: String,
    /// The kind of identification.
    pub id_kind: IdentityKind,
    /// The number for the entry.
    pub number: String,
    /// The issue place for the entry.
    pub issue_place: Option<String>,
    /// The issue date for the entry.
    pub issue_date: Option<UtcDateTime>,
    /// The expiration date for the entry.
    pub expiration_date: Option<UtcDateTime>,
    /// Collection of tags.
    pub tags: Option<HashSet<String>>,
    /// Optional note.
    pub note: Option<String>,
}

/// Generic payment record.
pub enum GenericPaymentRecord {
    /// Card payment information.
    Card {
        /// The label of the entry.
        label: String,
        /// The card number.
        number: String,
        /// The CVV code.
        code: String,
        /// An expiration date.
        expiration: Option<UtcDateTime>,
        /// The country for the entry.
        country: String,
        /// A note for the entry.
        note: Option<String>,
        /// Collection of tags.
        tags: Option<HashSet<String>>,
    },
    /// Bank account payment information.
    BankAccount {
        /// The label of the entry.
        label: String,
        /// The account holder of the entry.
        account_holder: String,
        /// The account number of the entry.
        account_number: String,
        /// The routing number of the entry.
        routing_number: String,
        /// The country for the entry.
        country: String,
        /// A note for the entry.
        note: Option<String>,
        /// Collection of tags.
        tags: Option<HashSet<String>>,
    },
}

impl GenericPaymentRecord {
    /// Get the label for the record.
    fn label(&self) -> &str {
        match self {
            Self::Card { label, .. } => label,
            Self::BankAccount { label, .. } => label,
        }
    }

    /// Get the tags for the record.
    fn tags(&mut self) -> &mut Option<HashSet<String>> {
        match self {
            Self::Card { tags, .. } => tags,
            Self::BankAccount { tags, .. } => tags,
        }
    }

    /// Get the note for the record.
    fn note(&mut self) -> &mut Option<String> {
        match self {
            Self::Card { note, .. } => note,
            Self::BankAccount { note, .. } => note,
        }
    }
}

/// Convert from generic password records.
pub struct GenericCsvConvert;

#[async_trait]
impl Convert for GenericCsvConvert {
    type Input = Vec<GenericCsvEntry>;

    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: &AccessKey,
    ) -> crate::Result<Vault> {
        let mut index = SearchIndex::new();
        let mut keeper = FileSystemAccessPoint::<Error>::new(vault);
        keeper.unlock(key).await?;

        let mut duplicates: HashMap<String, usize> = HashMap::new();

        for mut entry in source {
            // Handle duplicate labels by incrementing a counter
            let mut label = entry.label().to_owned();

            let rename_label = {
                if index
                    .find_by_label(keeper.vault().id(), &label, None)
                    .is_some()
                {
                    duplicates
                        .entry(label.clone())
                        .and_modify(|counter| *counter += 1)
                        .or_insert(1);
                    let counter = duplicates.get(&label).unwrap();
                    Some(format!("{} {}", label, counter))
                } else {
                    None
                }
            };

            if let Some(renamed) = rename_label {
                label = renamed;
            }

            let tags = entry.tags().take();
            let note = entry.note().take();
            let mut secret: Secret = entry.into();
            secret.user_data_mut().set_comment(note);
            let mut meta = SecretMeta::new(label, secret.kind());
            if let Some(tags) = tags {
                meta.set_tags(tags);
            }

            let id = SecretId::new_v4();
            let index_doc = index.prepare(keeper.id(), &id, &meta, &secret);
            let secret_data = SecretRow::new(id, meta, secret);
            keeper.create_secret(&secret_data).await?;
            index.commit(index_doc);
        }

        keeper.lock();
        Ok(keeper.into())
    }
}
