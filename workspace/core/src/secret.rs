//! Types used to represent vault meta data and secrets.
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use pem::Pem;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Serialize, Serializer,
};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
};
use totp_sos::TOTP;
use url::Url;
use uuid::Uuid;
use vcard4::{parse as parse_to_vcards, Vcard};

use crate::{
    signer::{BoxedSigner, SingleParty},
    Error, Result, Timestamp,
};

fn serialize_secret_string<S>(
    secret: &SecretString,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(secret.expose_secret())
}

fn serialize_secret_string_map<S>(
    secret: &HashMap<String, SecretString>,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = ser.serialize_map(Some(secret.len()))?;
    for (k, v) in secret {
        map.serialize_entry(k, v.expose_secret())?;
    }
    map.end()
}

fn serialize_secret_buffer<S>(
    secret: &SecretVec<u8>,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = ser.serialize_seq(Some(secret.expose_secret().len()))?;
    for element in secret.expose_secret() {
        seq.serialize_element(element)?;
    }
    seq.end()
}

/// Identifier for secrets.
pub type SecretId = Uuid;

/// Reference to a secret using an id or a named label.
#[derive(Debug, Clone)]
pub enum SecretRef {
    /// Secret identifier.
    Id(SecretId),
    /// Secret label.
    Name(String),
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for SecretRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(id) = Uuid::parse_str(s) {
            Ok(Self::Id(id))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

/// Unencrypted vault meta data.
#[derive(Default, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Private human-friendly description of the vault.
    label: String,
}

impl VaultMeta {
    /// Get the vault label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the vault label.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

impl Encode for VaultMeta {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_string(&self.label)?;
        Ok(())
    }
}

impl Decode for VaultMeta {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.label = reader.read_string()?;
        Ok(())
    }
}

/// Encapsulates the meta data for a secret.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    /// Kind of the secret.
    kind: u8,
    /// Last updated timestamp.
    #[serde(skip_deserializing)]
    last_updated: Timestamp,
    /// Human-friendly label for the secret.
    label: String,
    /// Collection of tags.
    tags: HashSet<String>,
    /// Additional usage notes for the secret.
    usage_notes: String,
}

impl PartialOrd for SecretMeta {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.label.partial_cmp(&other.label)
    }
}

impl SecretMeta {
    /// Create new meta data for a secret.
    pub fn new(label: String, kind: u8) -> Self {
        Self {
            label,
            kind,
            last_updated: Default::default(),
            tags: Default::default(),
            usage_notes: Default::default(),
        }
    }

    /// The label for the secret.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the label for the secret.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }

    /// The kind of the secret.
    pub fn kind(&self) -> &u8 {
        &self.kind
    }

    /// Update the last updated timestamp to now.
    pub fn touch(&mut self) {
        self.last_updated = Default::default();
    }

    /// The last updated date and time.
    pub fn last_updated(&self) -> &Timestamp {
        &self.last_updated
    }

    /// Get the tags.
    pub fn tags(&self) -> &HashSet<String> {
        &self.tags
    }

    /// Set the tags.
    pub fn set_tags(&mut self, tags: HashSet<String>) {
        self.tags = tags;
    }

    /// Get the usage notes.
    pub fn usage_notes(&self) -> &str {
        &self.usage_notes
    }

    /// Set the usage notes.
    pub fn set_usage_notes(&mut self, notes: String) {
        self.usage_notes = notes;
    }

    /// Get an abbreviated short name based
    /// on the kind of secret.
    pub fn short_name(&self) -> &str {
        match self.kind {
            kind::ACCOUNT => "ACCT",
            kind::NOTE => "NOTE",
            kind::LIST => "LIST",
            kind::FILE => "FILE",
            kind::PEM => "CERT",
            kind::PAGE => "PAGE",
            kind::PIN => "PIN",
            kind::SIGNER => "SIGNER",
            kind::CONTACT => "CONTACT",
            kind::TOTP => "TOTP",
            kind::CARD => "CARD",
            _ => unreachable!("unknown kind encountered in short name"),
        }
    }
}

impl Encode for SecretMeta {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_u8(self.kind)?;
        self.last_updated.encode(&mut *writer)?;
        writer.write_string(&self.label)?;
        writer.write_u32(self.tags.len() as u32)?;
        for tag in &self.tags {
            writer.write_string(tag)?;
        }
        writer.write_string(&self.usage_notes)?;
        Ok(())
    }
}

impl Decode for SecretMeta {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.kind = reader.read_u8()?;
        let mut last_updated: Timestamp = Default::default();
        last_updated.decode(&mut *reader)?;
        self.last_updated = last_updated;
        self.label = reader.read_string()?;
        let tag_count = reader.read_u32()?;
        for _ in 0..tag_count {
            let tag = reader.read_string()?;
            self.tags.insert(tag);
        }
        self.usage_notes = reader.read_string()?;
        Ok(())
    }
}

/// Constants for signer kinds.
mod signer_kind {
    pub(crate) const SINGLE_PARTY_ECDSA: u8 = 1;
}

/// Secret type that encapsulates a signing private key.
#[derive(Serialize, Deserialize)]
pub enum SecretSigner {
    /// Single party Ethereum-compatible ECDSA signing private key.
    #[serde(serialize_with = "serialize_secret_buffer")]
    SinglePartyEcdsa(SecretVec<u8>),
}

impl SecretSigner {
    /// Convert this secret into a type with signing capabilities.
    pub fn into_boxed_signer(self) -> Result<BoxedSigner> {
        match self {
            Self::SinglePartyEcdsa(key) => {
                let private_key: [u8; 32] =
                    key.expose_secret().as_slice().try_into()?;
                let signer: SingleParty = private_key.try_into()?;
                Ok(Box::new(signer))
            }
        }
    }
}

impl Default for SecretSigner {
    fn default() -> Self {
        Self::SinglePartyEcdsa(SecretVec::new(vec![]))
    }
}

impl Clone for SecretSigner {
    fn clone(&self) -> Self {
        match self {
            Self::SinglePartyEcdsa(buffer) => Self::SinglePartyEcdsa(
                SecretVec::new(buffer.expose_secret().to_vec()),
            ),
        }
    }
}

impl PartialEq for SecretSigner {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SinglePartyEcdsa(a), Self::SinglePartyEcdsa(b)) => {
                a.expose_secret() == b.expose_secret()
            }
        }
    }
}

impl Encode for SecretSigner {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let kind = match self {
            Self::SinglePartyEcdsa(_) => signer_kind::SINGLE_PARTY_ECDSA,
        };
        writer.write_u8(kind)?;

        match self {
            Self::SinglePartyEcdsa(buffer) => {
                writer.write_u32(buffer.expose_secret().len() as u32)?;
                writer.write_bytes(buffer.expose_secret())?;
            }
        }

        Ok(())
    }
}

impl Decode for SecretSigner {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            signer_kind::SINGLE_PARTY_ECDSA => {
                let buffer_len = reader.read_u32()?;
                let buffer = secrecy::Secret::new(
                    reader.read_bytes(buffer_len as usize)?,
                );
                *self = Self::SinglePartyEcdsa(buffer);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownSignerKind(kind),
                )))
            }
        }

        Ok(())
    }
}

/// Represents the various types of secret.
///
/// This implements the serde traits for the webassembly bindings
/// and so that the shell edit command can present a JSON representation
/// when a user wants to edit a secret.
#[derive(Serialize, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum Secret {
    /// A UTF-8 encoded note.
    #[serde(serialize_with = "serialize_secret_string")]
    Note(SecretString),
    /// A binary blob.
    File {
        /// File name.
        name: String,
        /// Mime type for the data.
        ///
        /// Use application/octet-stream if no mime-type is available.
        mime: String,
        /// The binary data.
        #[serde(serialize_with = "serialize_secret_buffer")]
        buffer: SecretVec<u8>,
    },
    /// Account with login password.
    Account {
        /// Name of the account.
        account: String,
        /// Optional URL associated with the account.
        url: Option<Url>,
        /// The account password.
        #[serde(serialize_with = "serialize_secret_string")]
        password: SecretString,
    },
    /// Collection of credentials as key/value pairs.
    #[serde(serialize_with = "serialize_secret_string_map")]
    List(HashMap<String, SecretString>),
    /// PEM encoded binary data.
    Pem(Vec<Pem>),
    /// A UTF-8 text document.
    Page {
        /// Title of the page.
        title: String,
        /// Mime type for the text, default is `text/markdown`.
        mime: String,
        /// The binary data.
        #[serde(serialize_with = "serialize_secret_string")]
        document: SecretString,
    },
    /// Personal identification number.
    ///
    /// Encoded as a string so there are no restrictions
    /// on the number of allowed digits.
    ///
    /// Client implementations should ensure the value
    /// only contains digits.
    Pin {
        /// The value for the PIN.
        #[serde(serialize_with = "serialize_secret_string")]
        number: SecretString,
    },
    /// Private signing key.
    Signer(SecretSigner),
    /// Contact vCard.
    Contact(Box<Vcard>),
    /// Time-based one-time passcode.
    Totp(TOTP),
    /// Credit or debit card.
    Card {
        /// The card number.
        number: String,
        /// The expiry data for the card.
        expiry: String,
        /// Card verification value.
        cvv: String,
        /// Name that appears on the card.
        name: Option<String>,
        /// ATM PIN.
        atm_pin: Option<String>,
    },
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        match self {
            Secret::Note(value) => Secret::Note(secrecy::Secret::new(
                value.expose_secret().to_owned(),
            )),
            Secret::File { name, mime, buffer } => Secret::File {
                name: name.to_owned(),
                mime: mime.to_owned(),
                buffer: secrecy::Secret::new(buffer.expose_secret().to_vec()),
            },
            Secret::Account {
                account,
                url,
                password,
            } => Secret::Account {
                account: account.to_owned(),
                url: url.clone(),
                password: secrecy::Secret::new(
                    password.expose_secret().to_owned(),
                ),
            },
            Secret::List(map) => {
                let copy = map
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.to_owned(),
                            secrecy::Secret::new(
                                v.expose_secret().to_owned(),
                            ),
                        )
                    })
                    .collect::<HashMap<_, _>>();
                Secret::List(copy)
            }
            Secret::Pem(pems) => Secret::Pem(pems.clone()),
            Secret::Page {
                title,
                mime,
                document,
            } => Secret::Page {
                title: title.to_owned(),
                mime: mime.to_owned(),
                document: secrecy::Secret::new(
                    document.expose_secret().to_owned(),
                ),
            },
            Secret::Pin { number } => Secret::Pin {
                number: secrecy::Secret::new(
                    number.expose_secret().to_owned(),
                ),
            },
            Secret::Signer(signer) => Secret::Signer(signer.clone()),
            Secret::Contact(vcard) => Secret::Contact(vcard.clone()),
            Secret::Totp(totp) => Secret::Totp(totp.clone()),
            Secret::Card {
                number,
                expiry,
                cvv,
                name,
                atm_pin,
            } => Secret::Card {
                number: number.clone(),
                expiry: expiry.clone(),
                cvv: cvv.clone(),
                name: name.clone(),
                atm_pin: atm_pin.clone(),
            },
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secret::Note(_) => f.debug_struct("Note").finish(),
            Secret::File { name, mime, .. } => f
                .debug_struct("File")
                .field("name", name)
                .field("mime", mime)
                .finish(),
            Secret::Account { account, url, .. } => f
                .debug_struct("Account")
                .field("account", account)
                .field("url", url)
                .finish(),
            Secret::List(map) => {
                let keys = map.keys().collect::<Vec<_>>();
                f.debug_struct("List").field("keys", &keys).finish()
            }
            Secret::Pem(pems) => {
                f.debug_struct("Pem").field("size", &pems.len()).finish()
            }
            Secret::Page { title, mime, .. } => f
                .debug_struct("Page")
                .field("title", title)
                .field("mime", mime)
                .finish(),
            Secret::Pin { .. } => f.debug_struct("PIN").finish(),
            Secret::Signer { .. } => f.debug_struct("Signer").finish(),
            Secret::Contact { .. } => f.debug_struct("Contact").finish(),
            Secret::Totp(_) => f.debug_struct("TOTP").finish(),
            Secret::Card { .. } => f.debug_struct("CARD").finish(),
        }
    }
}

impl Secret {
    /// Ensure all the bytes are ASCII digits.
    pub fn ensure_ascii_digits<B: AsRef<[u8]>>(bytes: B) -> Result<()> {
        for byte in bytes.as_ref() {
            if !byte.is_ascii_digit() {
                return Err(Error::NotDigit);
            }
        }
        Ok(())
    }

    /// Get a human readable name for the type of secret.
    pub fn type_name(kind: u8) -> &'static str {
        match kind {
            kind::NOTE => "Note",
            kind::FILE => "File",
            kind::ACCOUNT => "Account",
            kind::LIST => "List",
            kind::PEM => "Certificate",
            kind::PAGE => "Page",
            kind::PIN => "PIN",
            kind::SIGNER => "Signer",
            kind::CONTACT => "Contact",
            kind::TOTP => "TOTP",
            kind::CARD => "CARD",
            _ => unreachable!(),
        }
    }

    /// Get the kind identifier for this secret.
    pub fn kind(&self) -> u8 {
        match self {
            Secret::Note(_) => kind::NOTE,
            Secret::File { .. } => kind::FILE,
            Secret::Account { .. } => kind::ACCOUNT,
            Secret::List(_) => kind::LIST,
            Secret::Pem(_) => kind::PEM,
            Secret::Page { .. } => kind::PAGE,
            Secret::Pin { .. } => kind::PIN,
            Secret::Signer(_) => kind::SIGNER,
            Secret::Contact(_) => kind::CONTACT,
            Secret::Totp(_) => kind::TOTP,
            Secret::Card { .. } => kind::CARD,
        }
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Note(a), Self::Note(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            (
                Self::Account {
                    account: account_a,
                    url: url_a,
                    password: password_a,
                },
                Self::Account {
                    account: account_b,
                    url: url_b,
                    password: password_b,
                },
            ) => {
                account_a == account_b
                    && url_a == url_b
                    && password_a.expose_secret()
                        == password_b.expose_secret()
            }
            (
                Self::File {
                    name: name_a,
                    mime: mime_a,
                    buffer: buffer_a,
                },
                Self::File {
                    name: name_b,
                    mime: mime_b,
                    buffer: buffer_b,
                },
            ) => {
                name_a == name_b
                    && mime_a == mime_b
                    && buffer_a.expose_secret() == buffer_b.expose_secret()
            }
            (Self::List(a), Self::List(b)) => {
                a.iter().zip(b.iter()).all(|(a, b)| {
                    a.0 == b.0 && a.1.expose_secret() == b.1.expose_secret()
                })
            }
            (Self::Pem(a), Self::Pem(b)) => a
                .iter()
                .zip(b.iter())
                .all(|(a, b)| a.tag == b.tag && a.contents == b.contents),
            (
                Self::Page {
                    title: title_a,
                    mime: mime_a,
                    document: document_a,
                },
                Self::Page {
                    title: title_b,
                    mime: mime_b,
                    document: document_b,
                },
            ) => {
                title_a == title_b
                    && mime_a == mime_b
                    && document_a.expose_secret()
                        == document_b.expose_secret()
            }
            (Self::Pin { number: a }, Self::Pin { number: b }) => {
                a.expose_secret() == b.expose_secret()
            }
            (Self::Signer(a), Self::Signer(b)) => a.eq(b),
            (Self::Contact(a), Self::Contact(b)) => a.eq(b),
            (Self::Totp(a), Self::Totp(b)) => a.eq(b),
            (
                Self::Card {
                    number: number_a,
                    expiry: expiry_a,
                    cvv: cvv_a,
                    name: name_a,
                    atm_pin: atm_pin_a,
                },
                Self::Card {
                    number: number_b,
                    expiry: expiry_b,
                    cvv: cvv_b,
                    name: name_b,
                    atm_pin: atm_pin_b,
                },
            ) => {
                number_a == number_b
                    && expiry_a == expiry_b
                    && cvv_a == cvv_b
                    && name_a == name_b
                    && atm_pin_a == atm_pin_b
            }

            _ => false,
        }
    }
}
impl Eq for Secret {}

impl Default for Secret {
    fn default() -> Self {
        Self::Note(secrecy::Secret::new(String::new()))
    }
}

/// Type identifiers for the secret enum variants.
///
/// Used internally for encoding / decoding and client
/// implementations may use these to determine the type
/// of a secret.
pub mod kind {
    /// Account password type.
    pub const ACCOUNT: u8 = 1;
    /// Note UTF-8 text type.
    pub const NOTE: u8 = 2;
    /// List of credentials key / value pairs.
    pub const LIST: u8 = 3;
    /// Binary blob, may be file content.
    pub const FILE: u8 = 4;
    /// List of PEM encoded binary blobs.
    pub const PEM: u8 = 5;
    /// UTF-8 page that can be rendered to HTML.
    pub const PAGE: u8 = 6;
    /// Personal identification number.
    pub const PIN: u8 = 7;
    /// Private signing key.
    pub const SIGNER: u8 = 8;
    /// Contact vCard.
    pub const CONTACT: u8 = 9;
    /// Time-based one time passcode.
    pub const TOTP: u8 = 10;
    /// Credit or debit card.
    pub const CARD: u8 = 11;
}

impl Encode for Secret {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let kind = match self {
            Self::Note(_) => kind::NOTE,
            Self::File { .. } => kind::FILE,
            Self::Account { .. } => kind::ACCOUNT,
            Self::List { .. } => kind::LIST,
            Self::Pem(_) => kind::PEM,
            Self::Page { .. } => kind::PAGE,
            Self::Pin { .. } => kind::PIN,
            Self::Signer(_) => kind::SIGNER,
            Self::Contact(_) => kind::CONTACT,
            Self::Totp(_) => kind::TOTP,
            Self::Card { .. } => kind::CARD,
        };
        writer.write_u8(kind)?;

        match self {
            Self::Note(text) => {
                writer.write_string(text.expose_secret())?;
            }
            Self::File { name, mime, buffer } => {
                writer.write_string(name)?;
                writer.write_string(mime)?;
                writer.write_u32(buffer.expose_secret().len() as u32)?;
                writer.write_bytes(buffer.expose_secret())?;
            }
            Self::Account {
                account,
                password,
                url,
            } => {
                writer.write_string(account)?;
                writer.write_string(password.expose_secret())?;
                writer.write_bool(url.is_some())?;
                if let Some(url) = url {
                    writer.write_string(url)?;
                }
            }
            Self::List(list) => {
                writer.write_u32(list.len() as u32)?;
                for (k, v) in list {
                    writer.write_string(k)?;
                    writer.write_string(v.expose_secret())?;
                }
            }
            Self::Pem(pems) => {
                let value = pem::encode_many(pems);
                writer.write_string(value)?;
            }
            Self::Page {
                title,
                mime,
                document,
            } => {
                writer.write_string(title)?;
                writer.write_string(mime)?;
                writer.write_string(document.expose_secret())?;
            }
            Self::Pin { number } => {
                writer.write_string(number.expose_secret())?;
            }
            Self::Signer(signer) => {
                signer.encode(writer)?;
            }
            Self::Contact(vcard) => {
                writer.write_string(vcard.to_string())?;
            }
            Self::Totp(totp) => {
                let totp = serde_json::to_vec(totp).map_err(Box::from)?;
                writer.write_u32(totp.len() as u32)?;
                writer.write_bytes(totp)?;
            }
            Self::Card {
                number,
                expiry,
                cvv,
                name,
                atm_pin,
            } => {
                writer.write_string(number)?;
                writer.write_string(expiry)?;
                writer.write_string(cvv)?;

                writer.write_bool(name.is_some())?;
                if let Some(name) = name {
                    writer.write_string(name)?;
                }

                writer.write_bool(atm_pin.is_some())?;
                if let Some(atm_pin) = atm_pin {
                    writer.write_string(atm_pin)?;
                }
            }
        }
        Ok(())
    }
}

impl Decode for Secret {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            kind::NOTE => {
                *self =
                    Self::Note(secrecy::Secret::new(reader.read_string()?));
            }
            kind::FILE => {
                let name = reader.read_string()?;
                let mime = reader.read_string()?;
                let buffer_len = reader.read_u32()?;
                let buffer = secrecy::Secret::new(
                    reader.read_bytes(buffer_len as usize)?,
                );
                *self = Self::File { name, mime, buffer };
            }
            kind::ACCOUNT => {
                let account = reader.read_string()?;
                let password = secrecy::Secret::new(reader.read_string()?);
                let has_url = reader.read_bool()?;
                let url = if has_url {
                    Some(
                        Url::parse(&reader.read_string()?)
                            .map_err(Box::from)?,
                    )
                } else {
                    None
                };

                *self = Self::Account {
                    account,
                    password,
                    url,
                };
            }
            kind::LIST => {
                let list_len = reader.read_u32()?;
                let mut list = HashMap::with_capacity(list_len as usize);
                for _ in 0..list_len {
                    let key = reader.read_string()?;
                    let value = secrecy::Secret::new(reader.read_string()?);
                    list.insert(key, value);
                }

                *self = Self::List(list);
            }
            kind::PEM => {
                let value = reader.read_string()?;
                *self =
                    Self::Pem(pem::parse_many(&value).map_err(Box::from)?);
            }
            kind::PAGE => {
                let title = reader.read_string()?;
                let mime = reader.read_string()?;
                let document = secrecy::Secret::new(reader.read_string()?);
                *self = Self::Page {
                    title,
                    mime,
                    document,
                };
            }
            kind::PIN => {
                *self = Self::Pin {
                    number: secrecy::Secret::new(reader.read_string()?),
                };
            }
            kind::SIGNER => {
                let mut signer: SecretSigner = Default::default();
                signer.decode(reader)?;
                *self = Self::Signer(signer);
            }
            kind::CONTACT => {
                let vcard = reader.read_string()?;
                let mut cards = parse_to_vcards(&vcard).map_err(Box::from)?;
                let vcard = cards.remove(0);
                *self = Self::Contact(Box::new(vcard));
            }
            kind::TOTP => {
                let buffer_len = reader.read_u32()?;
                let buffer = reader.read_bytes(buffer_len as usize)?;
                let totp: TOTP =
                    serde_json::from_slice(&buffer).map_err(Box::from)?;
                *self = Self::Totp(totp);
            }
            kind::CARD => {
                let number = reader.read_string()?;
                let expiry = reader.read_string()?;
                let cvv = reader.read_string()?;

                let has_name = reader.read_bool()?;
                let name = if has_name {
                    Some(reader.read_string()?)
                } else {
                    None
                };

                let has_atm_pin = reader.read_bool()?;
                let atm_pin = if has_atm_pin {
                    Some(reader.read_string()?)
                } else {
                    None
                };

                *self = Self::Card {
                    number,
                    expiry,
                    cvv,
                    name,
                    atm_pin,
                };
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownSecretKind(kind),
                )))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        decode, encode,
        signer::{Signer, SingleParty},
    };
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    #[test]
    fn secret_serde() -> Result<()> {
        let secret = Secret::Note(secrecy::Secret::new(String::from("foo")));
        let value = serde_json::to_string_pretty(&secret)?;
        let result: Secret = serde_json::from_str(&value)?;
        assert_eq!(secret, result);
        Ok(())
    }

    #[test]
    fn secret_encode_note() -> Result<()> {
        let secret =
            Secret::Note(secrecy::Secret::new(String::from("My Note")));
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_file() -> Result<()> {
        let secret = Secret::File {
            name: "hello.txt".to_string(),
            mime: "text/plain".to_string(),
            buffer: secrecy::Secret::new("hello".as_bytes().to_vec()),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_account() -> Result<()> {
        let secret = Secret::Account {
            account: "Email".to_string(),
            url: Some("https://webmail.example.com".parse().unwrap()),
            password: secrecy::Secret::new("mock-password".to_string()),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);

        let secret_no_url = Secret::Account {
            account: "Email".to_string(),
            url: None,
            password: secrecy::Secret::new("mock-password".to_string()),
        };
        let encoded = encode(&secret_no_url)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret_no_url, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_list() -> Result<()> {
        let mut credentials = HashMap::new();
        credentials.insert(
            "API_KEY".to_owned(),
            secrecy::Secret::new("mock-access-key".to_owned()),
        );
        credentials.insert(
            "PROVIDER_KEY".to_owned(),
            secrecy::Secret::new("mock-provider-key".to_owned()),
        );
        let secret = Secret::List(credentials);

        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        // To assert consistently we must sort and to sort
        // we need to expose the underlying secret string
        // so we get an Ord implementation
        let (secret_a, secret_b) =
            if let (Secret::List(a), Secret::List(b)) = (secret, decoded) {
                let mut a = a
                    .into_iter()
                    .map(|(k, v)| (k, v.expose_secret().to_owned()))
                    .collect::<Vec<_>>();
                a.sort();
                let mut b = b
                    .into_iter()
                    .map(|(k, v)| (k, v.expose_secret().to_owned()))
                    .collect::<Vec<_>>();
                b.sort();
                (a, b)
            } else {
                unreachable!()
            };

        assert_eq!(secret_a, secret_b);
        Ok(())
    }

    #[test]
    fn secret_encode_pem() -> Result<()> {
        let certificate = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQCpeuNjpIxkaDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcVMjIwNzA3MDUxODIyWhcNMjMwNzA3MDUxODIyWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3ZwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCa
wvVkThyiguYjcz6SRBjC3b9rqAVG7K7plwAFP9Cd6LDJv1DVjJMmBh5jHJJGatIi
/1dyvMwgj+KXGRFKM27/ZboU7qGbzfJSzASabwjemoCrWbAo5eHxlpOAFFQi06KC
Gs0h9SPE5QjbAYqM1fCHAlvgQFNA2kutIpHq1M9QFthiofG3l7ZKqr695/DlHkcI
BSYIPDQK5MbuiDr7FlSPvB+Eq3fV92GOocsdew/mXsqQQvO4qHAoFIxtzDXjZWTV
P/iP5ybrE+zwofHouODQgs71snnR+bErbNeUezw5Ajl4+MgA9/OuTKXc84PLnflV
6W3f3FEumjgZlafasiTzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFLBPYNqOZ7y
XJ+kEcg4f9SADAaSaDWAzg5xm0/BWxI5md4axyBV90BuGilJxJQ13U2nAHHWNxEl
ub55VNuiLBHSbvigI1p/JZKB42PC+zcvy6Nj5BZnDnhmHgYcaRlnNhiPMaO8ymwb
y4lCg3P6cW1TcZLrA4H9vI+KR3sfV0KvlaQHqG330Rlud8zqIHnQShmb/eag+5eA
8jqTdL8LdVrc/Loykje1Jm733vvxjblWIVsUshNUq4F26lc6d3CbRDUnL5O+3YbU
L0sFErdHZ5BdOJJ1LS9zztUHvb1jaOJQBwaD+H+fbjUleLkKmELQODDiFekLAjRD
i1KQYQNRTzo=
-----END CERTIFICATE-----"#;

        let pems = pem::parse_many(certificate).unwrap();
        let secret = Secret::Pem(pems);
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_page() -> Result<()> {
        let secret = Secret::Page {
            title: "Welcome".to_string(),
            mime: "text/markdown".to_string(),
            document: secrecy::Secret::new("# Mock Page".to_owned()),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_signer() -> Result<()> {
        let signer = SingleParty::new_random();
        let secret_signer =
            SecretSigner::SinglePartyEcdsa(SecretVec::new(signer.to_bytes()));
        let secret = Secret::Signer(secret_signer);
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_contact() -> Result<()> {
        let text = r#"BEGIN:VCARD
VERSION:4.0
FN:John Doe
END:VCARD"#;

        let vcard: Vcard = text.try_into()?;
        let secret = Secret::Contact(Box::new(vcard));
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_totp() -> Result<()> {
        use totp_sos::{Algorithm, TOTP};

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "MockSecretWhichMustBeAtLeast80Bytes".as_bytes().to_vec(),
            "mock@example.com".to_string(),
            Some("MockIssuer".to_string()),
        )
        .unwrap();

        let secret = Secret::Totp(totp);
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_card() -> Result<()> {
        let secret = Secret::Card {
            number: "1234567890123456".to_string(),
            expiry: "03/64".to_string(),
            cvv: "123".to_string(),
            name: Some("Mock name".to_string()),
            atm_pin: Some("123456".to_string()),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }
}
