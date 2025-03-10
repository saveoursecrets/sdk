use crate::secret::{
    AgeVersion, FileContent, IdentityKind, Secret, SecretFlags, SecretMeta,
    SecretRow, SecretSigner, SecretType, UserData,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use secrecy::ExposeSecret;
use sos_core::{
    encoding::{decode_uuid, encoding_error},
    UtcDateTime,
};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Result},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};
use totp_rs::TOTP;
use url::Url;
use vcard4::{self};

const EMBEDDED_FILE: u8 = 1;
const EXTERNAL_FILE: u8 = 2;

/// Constants for signer kinds.
mod signer_kind {
    pub(crate) const SINGLE_PARTY_ECDSA: u8 = 1;
    pub(crate) const SINGLE_PARTY_ED25519: u8 = 2;
}

/// Utility for backwards compatible encoding
/// when the URL for an account/login secret only
/// supported a single URL.
///
/// Initially a single URL was encoded as a string,
/// when support for multiple URLs was added a Vec<Url>
/// is encoded to a JSON string.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum WebsiteUrl {
    One(Url),
    Many(Vec<Url>),
}

impl WebsiteUrl {
    /// Convert to a vector of URLs.
    pub fn to_vec(self) -> Vec<Url> {
        match self {
            Self::One(url) => vec![url],
            Self::Many(urls) => urls,
        }
    }
}

#[async_trait]
impl Encodable for SecretMeta {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let kind: u8 = self.kind.into();
        writer.write_u8(kind).await?;
        writer.write_u32(self.flags.bits()).await?;
        self.date_created.encode(&mut *writer).await?;
        self.last_updated.encode(&mut *writer).await?;
        writer.write_string(&self.label).await?;
        writer.write_u32(self.tags.len() as u32).await?;
        for tag in &self.tags {
            writer.write_string(tag).await?;
        }
        writer.write_bool(self.urn.is_some()).await?;
        if let Some(urn) = &self.urn {
            writer.write_string(urn).await?;
        }
        writer.write_bool(self.owner_id.is_some()).await?;
        if let Some(owner_id) = &self.owner_id {
            writer.write_string(owner_id).await?;
        }
        writer.write_bool(self.favorite).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for SecretMeta {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        self.kind = kind.try_into().map_err(encoding_error)?;
        self.flags = SecretFlags::from_bits(reader.read_u32().await?)
            .ok_or(crate::Error::InvalidSecretFlags)
            .map_err(encoding_error)?;
        let mut date_created: UtcDateTime = Default::default();
        date_created.decode(&mut *reader).await?;
        self.date_created = date_created;
        let mut last_updated: UtcDateTime = Default::default();
        last_updated.decode(&mut *reader).await?;
        self.last_updated = last_updated;
        self.label = reader.read_string().await?;
        let tag_count = reader.read_u32().await?;
        for _ in 0..tag_count {
            let tag = reader.read_string().await?;
            self.tags.insert(tag);
        }
        let has_urn = reader.read_bool().await?;
        if has_urn {
            let urn = reader.read_string().await?;
            self.urn = Some(urn.parse().map_err(encoding_error)?);
        }
        let has_owner_id = reader.read_bool().await?;
        if has_owner_id {
            let owner_id = reader.read_string().await?;
            self.owner_id = Some(owner_id.parse().map_err(encoding_error)?);
        }
        self.favorite = reader.read_bool().await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for SecretSigner {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let kind = match self {
            Self::SinglePartyEcdsa(_) => signer_kind::SINGLE_PARTY_ECDSA,
            Self::SinglePartyEd25519(_) => signer_kind::SINGLE_PARTY_ED25519,
        };
        writer.write_u8(kind).await?;

        match self {
            Self::SinglePartyEcdsa(buffer)
            | Self::SinglePartyEd25519(buffer) => {
                writer
                    .write_u32(buffer.expose_secret().len() as u32)
                    .await?;
                writer.write_bytes(buffer.expose_secret()).await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for SecretSigner {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            signer_kind::SINGLE_PARTY_ECDSA => {
                let buffer_len = reader.read_u32().await?;
                let buffer = secrecy::SecretBox::new(
                    reader.read_bytes(buffer_len as usize).await?.into(),
                );
                *self = Self::SinglePartyEcdsa(buffer);
            }
            signer_kind::SINGLE_PARTY_ED25519 => {
                let buffer_len = reader.read_u32().await?;
                let buffer = secrecy::SecretBox::new(
                    reader.read_bytes(buffer_len as usize).await?.into(),
                );
                *self = Self::SinglePartyEd25519(buffer);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown signer kind {}", kind),
                ));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Encodable for SecretRow {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.id.as_bytes()).await?;
        self.meta.encode(&mut *writer).await?;
        self.secret.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for SecretRow {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.id = decode_uuid(&mut *reader).await?;
        self.meta.decode(&mut *reader).await?;
        self.secret.decode(&mut *reader).await?;
        Ok(())
    }
}

async fn write_user_data<W: AsyncWrite + AsyncSeek + Unpin + Send>(
    user_data: &UserData,
    writer: &mut BinaryWriter<W>,
) -> Result<()> {
    writer.write_u32(user_data.len() as u32).await?;
    for field in user_data.fields() {
        field.encode(writer).await?;
    }
    writer.write_bool(user_data.comment.is_some()).await?;
    if let Some(comment) = &user_data.comment {
        writer.write_string(comment).await?;
    }
    writer.write_bool(user_data.recovery_note.is_some()).await?;
    if let Some(recovery_note) = &user_data.recovery_note {
        writer.write_string(recovery_note).await?;
    }
    Ok(())
}

async fn read_user_data<R: AsyncRead + AsyncSeek + Unpin + Send>(
    reader: &mut BinaryReader<R>,
) -> Result<UserData> {
    let mut user_data: UserData = Default::default();
    let count = reader.read_u32().await?;

    for _ in 0..count {
        let mut field: SecretRow = Default::default();
        field.decode(reader).await?;
        user_data.push(field);
    }
    let has_comment = reader.read_bool().await?;
    if has_comment {
        user_data.comment = Some(reader.read_string().await?);
    }
    let has_recovery_note = reader.read_bool().await?;
    if has_recovery_note {
        user_data.recovery_note = Some(reader.read_string().await?);
    }
    Ok(user_data)
}

#[async_trait]
impl Encodable for AgeVersion {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            Self::Version1 => writer.write_u8(1).await?,
        };
        Ok(())
    }
}

#[async_trait]
impl Decodable for AgeVersion {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            1 => {
                *self = Self::Version1;
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown age version {}", kind),
                ));
            }
        };
        Ok(())
    }
}

#[async_trait]
impl Encodable for FileContent {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            Self::Embedded {
                name,
                mime,
                buffer,
                checksum,
            } => {
                writer.write_u8(EMBEDDED_FILE).await?;
                writer.write_string(name).await?;
                writer.write_string(mime).await?;
                writer
                    .write_u32(buffer.expose_secret().len() as u32)
                    .await?;
                writer.write_bytes(buffer.expose_secret()).await?;
                writer.write_bytes(checksum).await?;
            }
            Self::External {
                name,
                mime,
                checksum,
                size,
                ..
            } => {
                writer.write_u8(EXTERNAL_FILE).await?;
                writer.write_string(name).await?;
                writer.write_string(mime).await?;
                writer.write_bytes(checksum).await?;
                writer.write_u64(size).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for FileContent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            EMBEDDED_FILE => {
                let name = reader.read_string().await?;
                let mime = reader.read_string().await?;
                let buffer_len = reader.read_u32().await?;
                let buffer = secrecy::SecretBox::new(
                    reader.read_bytes(buffer_len as usize).await?.into(),
                );
                let checksum: [u8; 32] = reader
                    .read_bytes(32)
                    .await?
                    .as_slice()
                    .try_into()
                    .map_err(encoding_error)?;
                *self = Self::Embedded {
                    name,
                    mime,
                    buffer,
                    checksum,
                };
            }
            EXTERNAL_FILE => {
                let name = reader.read_string().await?;
                let mime = reader.read_string().await?;
                let checksum: [u8; 32] = reader
                    .read_bytes(32)
                    .await?
                    .as_slice()
                    .try_into()
                    .map_err(encoding_error)?;
                let size = reader.read_u64().await?;
                *self = Self::External {
                    name,
                    mime,
                    checksum,
                    size,
                    path: None,
                };
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown file content type {}", kind),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for Secret {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let kind: u8 = self.kind().into();
        writer.write_u8(kind).await?;

        match self {
            Self::Account {
                account,
                password,
                url,
                user_data,
            } => {
                writer.write_string(account).await?;
                writer.write_string(password.expose_secret()).await?;

                // NOTE: must write this bool to be backwards
                // NOTE: compatible from when `url` was Option<Url>
                writer.write_bool(!url.is_empty()).await?;
                if !url.is_empty() {
                    let websites = WebsiteUrl::Many(url.clone());
                    let value = serde_json::to_string(&websites)?;
                    writer.write_string(value).await?;
                }
                write_user_data(user_data, writer).await?;
            }
            Self::Note { text, user_data } => {
                writer.write_string(text.expose_secret()).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::File {
                content, user_data, ..
            } => {
                content.encode(&mut *writer).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::List { items, user_data } => {
                writer.write_u32(items.len() as u32).await?;
                for (k, v) in items {
                    writer.write_string(k).await?;
                    writer.write_string(v.expose_secret()).await?;
                }
                write_user_data(user_data, writer).await?;
            }
            Self::Pem {
                certificates,
                user_data,
            } => {
                let value = pem::encode_many(certificates);
                writer.write_string(value).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::Page {
                title,
                mime,
                document,
                user_data,
            } => {
                writer.write_string(title).await?;
                writer.write_string(mime).await?;
                writer.write_string(document.expose_secret()).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::Identity {
                id_kind,
                number,
                issue_place,
                issue_date,
                expiry_date,
                user_data,
            } => {
                let id_kind: u8 = id_kind.into();
                writer.write_u8(id_kind).await?;
                writer.write_string(number.expose_secret()).await?;

                writer.write_bool(issue_place.is_some()).await?;
                if let Some(issue_place) = issue_place {
                    writer.write_string(issue_place).await?;
                }

                writer.write_bool(issue_date.is_some()).await?;
                if let Some(issue_date) = issue_date {
                    issue_date.encode(writer).await?;
                }

                writer.write_bool(expiry_date.is_some()).await?;
                if let Some(expiry_date) = expiry_date {
                    expiry_date.encode(writer).await?;
                }

                write_user_data(user_data, writer).await?;
            }
            Self::Signer {
                private_key,
                user_data,
            } => {
                private_key.encode(writer).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::Contact { vcard, user_data } => {
                writer.write_string(vcard.to_string()).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::Totp { totp, user_data } => {
                let totp =
                    serde_json::to_vec(totp).map_err(encoding_error)?;
                writer.write_u32(totp.len() as u32).await?;
                writer.write_bytes(totp).await?;
                write_user_data(user_data, writer).await?;
            }
            Self::Card {
                number,
                expiry,
                cvv,
                name,
                atm_pin,
                user_data,
            } => {
                writer.write_string(number.expose_secret()).await?;

                writer.write_bool(expiry.is_some()).await?;
                if let Some(expiry) = expiry {
                    expiry.encode(&mut *writer).await?;
                }
                writer.write_string(cvv.expose_secret()).await?;

                writer.write_bool(name.is_some()).await?;
                if let Some(name) = name {
                    writer.write_string(name.expose_secret()).await?;
                }

                writer.write_bool(atm_pin.is_some()).await?;
                if let Some(atm_pin) = atm_pin {
                    writer.write_string(atm_pin.expose_secret()).await?;
                }
                write_user_data(user_data, writer).await?;
            }
            Self::Bank {
                number,
                routing,
                iban,
                swift,
                bic,
                user_data,
            } => {
                writer.write_string(number.expose_secret()).await?;
                writer.write_string(routing.expose_secret()).await?;

                writer.write_bool(iban.is_some()).await?;
                if let Some(iban) = iban {
                    writer.write_string(iban.expose_secret()).await?;
                }

                writer.write_bool(swift.is_some()).await?;
                if let Some(swift) = swift {
                    writer.write_string(swift.expose_secret()).await?;
                }

                writer.write_bool(bic.is_some()).await?;
                if let Some(bic) = bic {
                    writer.write_string(bic.expose_secret()).await?;
                }
                write_user_data(user_data, writer).await?;
            }
            Self::Link {
                url,
                label,
                title,
                user_data,
            } => {
                writer.write_string(url.expose_secret()).await?;

                writer.write_bool(label.is_some()).await?;
                if let Some(label) = label {
                    writer.write_string(label.expose_secret()).await?;
                }

                writer.write_bool(title.is_some()).await?;
                if let Some(title) = title {
                    writer.write_string(title.expose_secret()).await?;
                }

                write_user_data(user_data, writer).await?;
            }
            Self::Password {
                password,
                name,
                user_data,
            } => {
                writer.write_string(password.expose_secret()).await?;

                writer.write_bool(name.is_some()).await?;
                if let Some(name) = name {
                    writer.write_string(name.expose_secret()).await?;
                }

                write_user_data(user_data, writer).await?;
            }
            Self::Age {
                version,
                key,
                user_data,
            } => {
                version.encode(writer).await?;
                writer.write_string(key.expose_secret()).await?;
                write_user_data(user_data, writer).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Secret {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind: SecretType =
            reader.read_u8().await?.try_into().map_err(encoding_error)?;
        match kind {
            SecretType::Note => {
                let text = reader.read_string().await?;
                let user_data = read_user_data(reader).await?;
                *self = Self::Note {
                    text: secrecy::SecretBox::new(text.into()),
                    user_data,
                };
            }
            SecretType::File => {
                let mut content: FileContent = Default::default();
                content.decode(&mut *reader).await?;
                let user_data = read_user_data(reader).await?;
                *self = Self::File { content, user_data };
            }
            SecretType::Account => {
                let account = reader.read_string().await?;
                let password = secrecy::SecretBox::new(
                    reader.read_string().await?.into(),
                );
                let has_url = reader.read_bool().await?;
                let url = if has_url {
                    let s = reader.read_string().await?;
                    // Original encoding was a String Url
                    match s.parse::<Url>() {
                        Ok(u) => WebsiteUrl::One(u).to_vec(),
                        // Newer encoding is JSON to support
                        // list of Urls
                        Err(_) => {
                            let value: WebsiteUrl = serde_json::from_str(&s)?;
                            value.to_vec()
                        }
                    }
                } else {
                    vec![]
                };

                let user_data = read_user_data(reader).await?;

                *self = Self::Account {
                    account,
                    password,
                    url,
                    user_data,
                };
            }
            SecretType::List => {
                let items_len = reader.read_u32().await?;
                let mut items = HashMap::with_capacity(items_len as usize);
                for _ in 0..items_len {
                    let key = reader.read_string().await?;
                    let value = secrecy::SecretBox::new(
                        reader.read_string().await?.into(),
                    );
                    items.insert(key, value);
                }
                let user_data = read_user_data(reader).await?;
                *self = Self::List { items, user_data };
            }
            SecretType::Pem => {
                let value = reader.read_string().await?;
                let user_data = read_user_data(reader).await?;
                *self = Self::Pem {
                    certificates: pem::parse_many(value)
                        .map_err(encoding_error)?,

                    user_data,
                };
            }
            SecretType::Page => {
                let title = reader.read_string().await?;
                let mime = reader.read_string().await?;
                let document = secrecy::SecretBox::new(
                    reader.read_string().await?.into(),
                );
                let user_data = read_user_data(reader).await?;
                *self = Self::Page {
                    title,
                    mime,
                    document,
                    user_data,
                };
            }
            SecretType::Identity => {
                let id_kind = reader.read_u8().await?;
                let id_kind: IdentityKind =
                    id_kind.try_into().map_err(encoding_error)?;

                let number = reader.read_string().await?.into();

                let has_issue_place = reader.read_bool().await?;
                let issue_place = if has_issue_place {
                    Some(reader.read_string().await?)
                } else {
                    None
                };

                let has_issue_date = reader.read_bool().await?;
                let issue_date = if has_issue_date {
                    let mut timestamp: UtcDateTime = Default::default();
                    timestamp.decode(&mut *reader).await?;
                    Some(timestamp)
                } else {
                    None
                };

                let has_expiry_date = reader.read_bool().await?;
                let expiry_date = if has_expiry_date {
                    let mut timestamp: UtcDateTime = Default::default();
                    timestamp.decode(&mut *reader).await?;
                    Some(timestamp)
                } else {
                    None
                };

                let user_data = read_user_data(reader).await?;
                *self = Self::Identity {
                    id_kind,
                    number,
                    issue_place,
                    issue_date,
                    expiry_date,
                    user_data,
                };
            }
            SecretType::Signer => {
                let mut private_key: SecretSigner = Default::default();
                private_key.decode(reader).await?;
                let user_data = read_user_data(reader).await?;
                *self = Self::Signer {
                    private_key,
                    user_data,
                };
            }
            SecretType::Contact => {
                let vcard = reader.read_string().await?;
                let mut cards =
                    vcard4::parse(vcard).map_err(encoding_error)?;
                let vcard = cards.remove(0);
                let user_data = read_user_data(reader).await?;
                *self = Self::Contact {
                    vcard: Box::new(vcard),
                    user_data,
                };
            }
            SecretType::Totp => {
                let buffer_len = reader.read_u32().await?;
                let buffer = reader.read_bytes(buffer_len as usize).await?;
                let totp: TOTP = serde_json::from_slice(&buffer)
                    .map_err(encoding_error)?;
                let user_data = read_user_data(reader).await?;
                *self = Self::Totp { totp, user_data };
            }
            SecretType::Card => {
                let number = reader.read_string().await?.into();
                let has_expiry = reader.read_bool().await?;
                let expiry = if has_expiry {
                    let mut expiry: UtcDateTime = Default::default();
                    expiry.decode(reader).await?;
                    Some(expiry)
                } else {
                    None
                };
                let cvv = reader.read_string().await?.into();

                let has_name = reader.read_bool().await?;
                let name = if has_name {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let has_atm_pin = reader.read_bool().await?;
                let atm_pin = if has_atm_pin {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let user_data = read_user_data(reader).await?;
                *self = Self::Card {
                    number,
                    expiry,
                    cvv,
                    name,
                    atm_pin,
                    user_data,
                };
            }
            SecretType::Bank => {
                let number = reader.read_string().await?.into();
                let routing = reader.read_string().await?.into();

                let has_iban = reader.read_bool().await?;
                let iban = if has_iban {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let has_swift = reader.read_bool().await?;
                let swift = if has_swift {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let has_bic = reader.read_bool().await?;
                let bic = if has_bic {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let user_data = read_user_data(reader).await?;
                *self = Self::Bank {
                    number,
                    routing,
                    iban,
                    swift,
                    bic,
                    user_data,
                };
            }
            SecretType::Link => {
                let url = reader.read_string().await?.into();

                let has_label = reader.read_bool().await?;
                let label = if has_label {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let has_title = reader.read_bool().await?;
                let title = if has_title {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let user_data = read_user_data(reader).await?;
                *self = Self::Link {
                    url,
                    label,
                    title,
                    user_data,
                };
            }
            SecretType::Password => {
                let password = reader.read_string().await?.into();

                let has_name = reader.read_bool().await?;
                let name = if has_name {
                    Some(reader.read_string().await?.into())
                } else {
                    None
                };

                let user_data = read_user_data(reader).await?;
                *self = Self::Password {
                    password,
                    name,
                    user_data,
                };
            }
            SecretType::Age => {
                let mut version: AgeVersion = Default::default();
                version.decode(reader).await?;
                let id = reader.read_string().await?;

                // Make sure it's a valid x25519 identity
                let _: age::x25519::Identity =
                    id.parse().map_err(|s: &str| {
                        encoding_error(crate::Error::InvalidX25519Identity(
                            s.to_string(),
                        ))
                    })?;

                let key = id.into();

                let user_data = read_user_data(reader).await?;
                *self = Self::Age {
                    version,
                    key,
                    user_data,
                };
            }
        }
        Ok(())
    }
}
