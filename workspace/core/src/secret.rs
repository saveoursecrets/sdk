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
use std::{collections::HashMap, fmt, str::FromStr};
use url::Url;
use uuid::Uuid;

use crate::Error;

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
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
    /// The human-friendly label for the vault.
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
#[derive(
    Debug,
    Serialize,
    Deserialize,
    Default,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
)]
pub struct SecretMeta {
    /// Human-friendly label for the secret.
    label: String,
    /// Kind of the secret.
    kind: u8,
}

impl SecretMeta {
    /// Create new meta data for a secret.
    pub fn new(label: String, kind: u8) -> Self {
        Self { label, kind }
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

    /// Get an abbreviated short name based
    /// on the kind of secret.
    pub fn short_name(&self) -> &str {
        match self.kind {
            kind::ACCOUNT => "ACCT",
            kind::NOTE => "NOTE",
            kind::LIST => "LIST",
            kind::FILE => "FILE",
            _ => unreachable!("unknown kind encountered in short name"),
        }
    }
}

impl Encode for SecretMeta {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_u8(self.kind)?;
        writer.write_string(&self.label)?;
        Ok(())
    }
}

impl Decode for SecretMeta {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.kind = reader.read_u8()?;
        self.label = reader.read_string()?;
        Ok(())
    }
}

/// Encapsulates a secret.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
                    .into_iter()
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
        }
    }
}

impl Secret {
    /// Get a human readable name for the type of secret.
    pub fn type_name(kind: u8) -> &'static str {
        match kind {
            kind::NOTE => "Note",
            kind::FILE => "File",
            kind::ACCOUNT => "Account",
            kind::LIST => "List",
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
    pub const ACCOUNT: u8 = 0x01;
    /// Note UTF-8 text type.
    pub const NOTE: u8 = 0x02;
    /// List of credentials key / value pairs.
    pub const LIST: u8 = 0x03;
    /// Binary blob, may be file content.
    pub const FILE: u8 = 0x04;
    /// List of PEM encoded binary blobs.
    pub const PEM: u8 = 0x05;
}

impl Encode for Secret {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let kind = match self {
            Self::Note(_) => kind::NOTE,
            Self::File { .. } => kind::FILE,
            Self::Account { .. } => kind::ACCOUNT,
            Self::List { .. } => kind::LIST,
            Self::Pem(_) => kind::PEM,
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

                // FIXME: ensure name is handled correctly
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
    use anyhow::Result;

    #[test]
    fn secret_serde() -> Result<()> {
        let secret = Secret::Note(secrecy::Secret::new(String::from("foo")));
        let value = serde_json::to_string_pretty(&secret)?;
        let result: Secret = serde_json::from_str(&value)?;
        assert_eq!(secret, result);
        Ok(())
    }
}
