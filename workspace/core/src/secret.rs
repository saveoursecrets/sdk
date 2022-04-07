//! Types used to represent vault meta data and secrets.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use url::Url;
use uuid::Uuid;

use crate::Error;

/// Represents either a uuid or a named label.
#[derive(Debug)]
pub enum UuidOrName {
    /// A unique identifier.
    Uuid(Uuid),
    /// The name of a label.
    Name(String),
}

impl FromStr for UuidOrName {
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
pub struct MetaData {
    /// The human-friendly label for the vault.
    label: String,
    /// Map of secret identifiers to meta data about the secret.
    secrets: HashMap<Uuid, SecretMeta>,
}

impl MetaData {
    /// Get the vault label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the secrets map.
    pub fn secrets(&self) -> &HashMap<Uuid, SecretMeta> {
        &self.secrets
    }

    /// Get the vault label.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }

    /// Add meta data for a secret.
    pub fn add_secret_meta(&mut self, uuid: Uuid, meta: SecretMeta) {
        self.secrets.insert(uuid, meta);
    }

    /// Get meta data for a secret.
    pub fn get_secret_meta(&self, uuid: &Uuid) -> Option<&SecretMeta> {
        self.secrets.get(uuid)
    }

    /// Remove meta data for a secret.
    pub fn remove_secret_meta(&mut self, uuid: &Uuid) {
        self.secrets.remove(uuid);
    }

    /// Find secret meta by label.
    pub fn find_by_label(&self, label: &str) -> Option<&SecretMeta> {
        self.secrets.values().find(|m| m.label() == label)
    }

    /// Find secret meta by uuid or label.
    pub fn find_by_uuid_or_label(
        &self,
        target: &UuidOrName,
    ) -> Option<(Uuid, &SecretMeta)> {
        match target {
            UuidOrName::Uuid(uuid) => {
                self.secrets.get(uuid).map(|v| (*uuid, v))
            }
            UuidOrName::Name(name) => self.secrets.iter().find_map(|(k, v)| {
                if v.label() == name {
                    return Some((*k, v));
                } else {
                    None
                }
            }),
        }
    }
}

impl Encode for MetaData {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.label.serialize(&mut *ser)?;
        self.secrets.serialize(&mut *ser)?;
        Ok(())
    }
}

impl Decode for MetaData {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.label = Deserialize::deserialize(&mut *de)?;
        self.secrets = Deserialize::deserialize(&mut *de)?;
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

    /// The kind of the secret.
    pub fn kind(&self) -> &u8 {
        &self.kind
    }
}

/// Encapsulates a secret.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Secret {
    /// A UTF-8 encoded note.
    Text(String),
    /// A binary blob.
    Blob {
        /// The binary data.
        buffer: Vec<u8>,
        /// Optional mime type for the data.
        mime: Option<String>,
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
    Credentials(HashMap<String, String>),
}

impl Secret {
    /// Get a human readable name for the type of secret.
    pub fn type_name(kind: u8) -> &'static str {
        match kind {
            kind::TEXT => "Note",
            kind::BLOB => "File",
            kind::ACCOUNT => "Account",
            kind::CREDENTIALS => "Credentials",
            _ => unreachable!(),
        }
    }

    /// Get the kind identifier for this secret.
    pub fn kind(&self) -> u8 {
        match self {
            Secret::Text(_) => kind::TEXT,
            Secret::Blob { .. } => kind::BLOB,
            Secret::Account { .. } => kind::ACCOUNT,
            Secret::Credentials(_) => kind::CREDENTIALS,
        }
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self::Text(String::new())
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
    pub const TEXT: u8 = 0x02;
    /// List of credentials key / value pairs.
    pub const CREDENTIALS: u8 = 0x03;
    /// Binary blob, may be file content.
    pub const BLOB: u8 = 0x04;
}

impl Encode for Secret {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let kind = match self {
            Self::Text(_) => kind::TEXT,
            Self::Blob { .. } => kind::BLOB,
            Self::Account { .. } => kind::ACCOUNT,
            Self::Credentials { .. } => kind::CREDENTIALS,
        };
        ser.writer.write_u8(kind)?;

        match self {
            Self::Text(text) => {
                ser.writer.write_string(text)?;
            }
            Self::Blob { buffer, mime } => {
                ser.writer.write_u32(buffer.len() as u32)?;
                ser.writer.write_bytes(buffer)?;
                ser.writer.write_bool(mime.is_some())?;
                if let Some(mime) = mime {
                    ser.writer.write_string(mime)?;
                }
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
            Self::Credentials(list) => {
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
            kind::TEXT => {
                *self = Self::Text(de.reader.read_string()?);
            }
            kind::BLOB => {
                let buffer_len = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(buffer_len as usize)?;
                let has_mime = de.reader.read_bool()?;
                let mime = if has_mime {
                    Some(de.reader.read_string()?)
                } else {
                    None
                };

                *self = Self::Blob { buffer, mime };
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
            kind::CREDENTIALS => {
                let list_len = de.reader.read_u32()?;
                let mut list: HashMap<String, String> =
                    HashMap::with_capacity(list_len as usize);
                for _ in 0..list_len {
                    let key = de.reader.read_string()?;
                    let value = de.reader.read_string()?;
                    list.insert(key, value);
                }

                *self = Self::Credentials(list);
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
