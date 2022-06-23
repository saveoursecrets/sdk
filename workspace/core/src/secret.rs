//! Types used to represent vault meta data and secrets.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, str::FromStr};
use url::Url;
use uuid::Uuid;

use crate::Error;

/// Identifier for secrets.
pub type SecretId = Uuid;

/// Reference to a secret using an id or a named label.
#[derive(Debug)]
pub enum SecretRef {
    /// Secret identifier.
    Uuid(SecretId),
    /// Secret label.
    Name(String),
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uuid(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for SecretRef {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(uuid) = Uuid::parse_str(s) {
            Ok(Self::Uuid(uuid))
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
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.label.serialize(&mut *ser)?;
        Ok(())
    }
}

impl Decode for VaultMeta {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.label = Deserialize::deserialize(&mut *de)?;
        Ok(())
    }
}

/// Encapsulates the meta data for a secret.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Eq, PartialEq)]
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
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_u8(self.kind)?;
        self.label.serialize(&mut *ser)?;
        Ok(())
    }
}

impl Decode for SecretMeta {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.kind = de.reader.read_u8()?;
        self.label = Deserialize::deserialize(&mut *de)?;
        Ok(())
    }
}

/// Encapsulates a secret.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Secret {
    /// A UTF-8 encoded note.
    Note(String),
    /// A binary blob.
    File {
        /// File name.
        name: String,
        /// Mime type for the data.
        ///
        /// Use application/octet-stream if no mime-type is available.
        mime: String,
        /// The binary data.
        buffer: Vec<u8>,
    },
    /// Account with login password.
    Account {
        /// Name of the account.
        account: String,
        /// Optional URL associated with the account.
        url: Option<Url>,
        /// The account password.
        password: String,
    },
    /// Collection of credentials as key/value pairs.
    List(HashMap<String, String>),
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
        }
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self::Note(String::new())
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
}

impl Encode for Secret {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let kind = match self {
            Self::Note(_) => kind::NOTE,
            Self::File { .. } => kind::FILE,
            Self::Account { .. } => kind::ACCOUNT,
            Self::List { .. } => kind::LIST,
        };
        ser.writer.write_u8(kind)?;

        match self {
            Self::Note(text) => {
                ser.writer.write_string(text)?;
            }
            Self::File { name, mime, buffer } => {
                ser.writer.write_string(name)?;
                ser.writer.write_string(mime)?;
                ser.writer.write_u32(buffer.len() as u32)?;
                ser.writer.write_bytes(buffer)?;
            }
            Self::Account {
                account,
                password,
                url,
            } => {
                ser.writer.write_string(account)?;
                ser.writer.write_string(password)?;
                ser.writer.write_bool(url.is_some())?;
                if let Some(url) = url {
                    ser.writer.write_string(url)?;
                }
            }
            Self::List(list) => {
                ser.writer.write_u32(list.len() as u32)?;
                for (k, v) in list {
                    ser.writer.write_string(k)?;
                    ser.writer.write_string(v)?;
                }
            }
        }

        Ok(())
    }
}

impl Decode for Secret {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let kind = de.reader.read_u8()?;
        match kind {
            kind::NOTE => {
                *self = Self::Note(de.reader.read_string()?);
            }
            kind::FILE => {
                let name = de.reader.read_string()?;
                let mime = de.reader.read_string()?;
                let buffer_len = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(buffer_len as usize)?;

                // FIXME: ensure name is handled correctly
                *self = Self::File { name, mime, buffer };
            }
            kind::ACCOUNT => {
                let account = de.reader.read_string()?;
                let password = de.reader.read_string()?;
                let has_url = de.reader.read_bool()?;
                let url = if has_url {
                    Some(
                        Url::parse(&de.reader.read_string()?)
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
                let list_len = de.reader.read_u32()?;
                let mut list: HashMap<String, String> =
                    HashMap::with_capacity(list_len as usize);
                for _ in 0..list_len {
                    let key = de.reader.read_string()?;
                    let value = de.reader.read_string()?;
                    list.insert(key, value);
                }

                *self = Self::List(list);
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
