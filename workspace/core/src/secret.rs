//! Types used to represent vault meta data and secrets.
use binary_rw::{BinaryReader, BinaryWriter};

use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

use crate::{
    Result, Error,
    traits::{Decode, Encode}};

/// Unencrypted vault meta data.
#[derive(Default)]
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

    /// Get the vault label.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }

    /// Add meta data for a secret.
    pub fn add_secret_meta(&mut self, uuid: Uuid, meta: SecretMeta) {
        self.secrets.insert(uuid, meta);
    }

    /// Get meta data for a secret.
    pub fn get_secret_meta(&mut self, uuid: &Uuid) -> Option<&SecretMeta> {
        self.secrets.get(uuid)
    }
}

impl Encode for MetaData {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_string(&self.label)?;
        writer.write_usize(self.secrets.len())?;
        for (key, value) in self.secrets.iter() {
            writer.write_string(key.to_string())?;
            value.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for MetaData {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.label = reader.read_string()?;
        let secrets_len = reader.read_usize()?;
        for _ in 0..secrets_len {
            let key = Uuid::parse_str(&reader.read_string()?)?;
            let mut value: SecretMeta = Default::default();
            value.decode(reader)?;
            self.secrets.insert(key, value);
        }
        Ok(())
    }
}

/// Encapsulates the meta data for a secret.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SecretMeta {
    /// Human-friendly label for the secret.
    label: String,
}

impl SecretMeta {
    /// Create new meta data for a secret.
    pub fn new(label: String) -> Self {
        Self {
            label,
        }
    }
}

impl Encode for SecretMeta {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_string(&self.label)?;
        Ok(())
    }
}

impl Decode for SecretMeta {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.label = reader.read_string()?;
        Ok(())
    }
}

/// Encapsulates a secret.
#[derive(Debug, Eq, PartialEq)]
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

impl Default for Secret {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

mod secret_kind {
    pub(super) const TEXT: u8 = 0x01;
    pub(super) const BLOB: u8 = 0x02;
    pub(super) const ACCOUNT: u8 = 0x03;
    pub(super) const CREDENTIALS: u8 = 0x04;
}

impl Encode for Secret {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        let kind = match self {
            Self::Text(_) => secret_kind::TEXT,
            Self::Blob { .. } => secret_kind::BLOB,
            Self::Account { .. } => secret_kind::ACCOUNT,
            Self::Credentials { .. } => secret_kind::CREDENTIALS,
        };
        writer.write_u8(kind)?;

        match self {
            Self::Text(text) => {
                writer.write_string(text)?;
            }
            Self::Blob { buffer, mime } => {
                writer.write_usize(buffer.len())?;
                writer.write_bytes(buffer)?;
                writer.write_bool(mime.is_some())?;
                if let Some(mime) = mime {
                    writer.write_string(mime)?;
                }
            }
            Self::Account {
                account,
                password,
                url,
            } => {
                writer.write_string(account)?;
                writer.write_string(password)?;
                writer.write_bool(url.is_some())?;
                if let Some(url) = url {
                    writer.write_string(url.to_string())?;
                }
            }
            Self::Credentials(list) => {
                writer.write_usize(list.len())?;
                for (k, v) in list {
                    writer.write_string(k)?;
                    writer.write_string(v)?;
                }
            }
        }

        Ok(())
    }
}

impl Decode for Secret {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let kind = reader.read_u8()?;
        match kind {
            secret_kind::TEXT => {
                *self = Self::Text(reader.read_string()?);
            }
            secret_kind::BLOB => {
                let buffer_len = reader.read_usize()?;
                let buffer = reader.read_bytes(buffer_len)?;
                let has_mime = reader.read_bool()?;
                let mime = if has_mime {
                    Some(reader.read_string()?)
                } else {
                    None
                };

                *self = Self::Blob {buffer, mime};
            }
            secret_kind::ACCOUNT => {
                let account = reader.read_string()?;
                let password = reader.read_string()?;
                let has_url = reader.read_bool()?;
                let url = if has_url {
                    Some(Url::parse(&reader.read_string()?)?)
                } else {
                    None
                };

                *self = Self::Account {account, password, url};
            }
            secret_kind::CREDENTIALS => {
                let list_len = reader.read_usize()?;
                let mut list: HashMap<String, String> = HashMap::with_capacity(list_len);
                for _ in 0..list_len {
                    let key = reader.read_string()?;
                    let value = reader.read_string()?;
                    list.insert(key, value);
                }

                *self = Self::Credentials(list);
            }
            _ => {
                return Err(Error::UnknownSecretKind(kind))
            }
        }
        Ok(())
    }
}
