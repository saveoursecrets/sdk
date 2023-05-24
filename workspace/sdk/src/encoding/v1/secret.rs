use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use secrecy::{ExposeSecret, SecretString};

use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
};
use totp_sos::TOTP;
use url::Url;

use uuid::Uuid;
use vcard4::{self};

use crate::{
    vault::secret::{
        AgeVersion, FileContent, IdentityKind, Secret, SecretFlags,
        SecretMeta, SecretRow, SecretSigner, SecretType, UserData,
    },
    Error, Timestamp,
};

const EMBEDDED_FILE: u8 = 1;
const EXTERNAL_FILE: u8 = 2;

/// Constants for signer kinds.
mod signer_kind {
    pub(crate) const SINGLE_PARTY_ECDSA: u8 = 1;
    pub(crate) const SINGLE_PARTY_ED25519: u8 = 2;
}

impl Encode for SecretMeta {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let kind: u8 = self.kind.into();
        writer.write_u8(kind)?;
        writer.write_u32(self.flags.bits())?;
        self.date_created.encode(&mut *writer)?;
        self.last_updated.encode(&mut *writer)?;
        writer.write_string(&self.label)?;
        writer.write_u32(self.tags.len() as u32)?;
        for tag in &self.tags {
            writer.write_string(tag)?;
        }
        writer.write_bool(self.urn.is_some())?;
        if let Some(urn) = &self.urn {
            writer.write_string(urn)?;
        }
        writer.write_bool(self.owner_id.is_some())?;
        if let Some(owner_id) = &self.owner_id {
            writer.write_string(owner_id)?;
        }
        writer.write_bool(self.favorite)?;
        Ok(())
    }
}

impl Decode for SecretMeta {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        self.kind = kind.try_into().map_err(Box::from)?;
        self.flags = SecretFlags::from_bits(reader.read_u32()?)
            .ok_or(Error::InvalidSecretFlags)
            .map_err(Box::from)?;
        let mut date_created: Timestamp = Default::default();
        date_created.decode(&mut *reader)?;
        self.date_created = date_created;
        let mut last_updated: Timestamp = Default::default();
        last_updated.decode(&mut *reader)?;
        self.last_updated = last_updated;
        self.label = reader.read_string()?;
        let tag_count = reader.read_u32()?;
        for _ in 0..tag_count {
            let tag = reader.read_string()?;
            self.tags.insert(tag);
        }
        let has_urn = reader.read_bool()?;
        if has_urn {
            let urn = reader.read_string()?;
            self.urn = Some(urn.parse().map_err(Box::from)?);
        }
        let has_owner_id = reader.read_bool()?;
        if has_owner_id {
            let owner_id = reader.read_string()?;
            self.owner_id = Some(owner_id.parse().map_err(Box::from)?);
        }
        self.favorite = reader.read_bool()?;
        Ok(())
    }
}

impl Encode for SecretSigner {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let kind = match self {
            Self::SinglePartyEcdsa(_) => signer_kind::SINGLE_PARTY_ECDSA,
            Self::SinglePartyEd25519(_) => signer_kind::SINGLE_PARTY_ED25519,
        };
        writer.write_u8(kind)?;

        match self {
            Self::SinglePartyEcdsa(buffer)
            | Self::SinglePartyEd25519(buffer) => {
                writer.write_u32(buffer.expose_secret().len() as u32)?;
                writer.write_bytes(buffer.expose_secret())?;
            }
        }

        Ok(())
    }
}

impl Decode for SecretSigner {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            signer_kind::SINGLE_PARTY_ECDSA => {
                let buffer_len = reader.read_u32()?;
                let buffer = secrecy::Secret::new(
                    reader.read_bytes(buffer_len as usize)?,
                );
                *self = Self::SinglePartyEcdsa(buffer);
            }
            signer_kind::SINGLE_PARTY_ED25519 => {
                let buffer_len = reader.read_u32()?;
                let buffer = secrecy::Secret::new(
                    reader.read_bytes(buffer_len as usize)?,
                );
                *self = Self::SinglePartyEd25519(buffer);
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

impl Encode for SecretRow {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(self.id.as_bytes())?;
        self.meta.encode(&mut *writer)?;
        self.secret.encode(&mut *writer)?;
        Ok(())
    }
}

impl Decode for SecretRow {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        self.id = Uuid::from_bytes(uuid);
        self.meta.decode(&mut *reader)?;
        self.secret.decode(&mut *reader)?;
        Ok(())
    }
}

fn write_user_data<W: Write + Seek>(
    user_data: &UserData,
    writer: &mut BinaryWriter<W>,
) -> BinaryResult<()> {
    writer.write_u32(user_data.len() as u32)?;
    for field in user_data.fields() {
        field.encode(writer)?;
    }
    writer.write_bool(user_data.comment.is_some())?;
    if let Some(comment) = &user_data.comment {
        writer.write_string(comment)?;
    }
    writer.write_bool(user_data.recovery_note.is_some())?;
    if let Some(recovery_note) = &user_data.recovery_note {
        writer.write_string(recovery_note)?;
    }
    Ok(())
}

fn read_user_data<R: Read + Seek>(
    reader: &mut BinaryReader<R>,
) -> BinaryResult<UserData> {
    let mut user_data: UserData = Default::default();
    let count = reader.read_u32()?;

    for _ in 0..count {
        let mut field: SecretRow = Default::default();
        field.decode(reader)?;
        user_data.push(field);
    }
    let has_comment = reader.read_bool()?;
    if has_comment {
        user_data.comment = Some(reader.read_string()?);
    }
    let has_recovery_note = reader.read_bool()?;
    if has_recovery_note {
        user_data.recovery_note = Some(reader.read_string()?);
    }
    Ok(user_data)
}

impl Encode for AgeVersion {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        match self {
            Self::Version1 => writer.write_u8(1)?,
        };
        Ok(())
    }
}

impl Decode for AgeVersion {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            1 => {
                *self = Self::Version1;
            }
            _ => {
                return Err(BinaryError::Boxed(Box::new(
                    Error::UnknownAgeVersion(kind),
                )))
            }
        };
        Ok(())
    }
}

impl Encode for FileContent {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        match self {
            Self::Embedded {
                name,
                mime,
                buffer,
                checksum,
            } => {
                writer.write_u8(EMBEDDED_FILE)?;
                writer.write_string(name)?;
                writer.write_string(mime)?;
                writer.write_u32(buffer.expose_secret().len() as u32)?;
                writer.write_bytes(buffer.expose_secret())?;
                writer.write_bytes(checksum)?;
            }
            Self::External {
                name,
                mime,
                checksum,
                size,
                ..
            } => {
                writer.write_u8(EXTERNAL_FILE)?;
                writer.write_string(name)?;
                writer.write_string(mime)?;
                writer.write_bytes(checksum)?;
                writer.write_u64(size)?;
            }
        }
        Ok(())
    }
}

impl Decode for FileContent {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            EMBEDDED_FILE => {
                let name = reader.read_string()?;
                let mime = reader.read_string()?;
                let buffer_len = reader.read_u32()?;
                let buffer = secrecy::Secret::new(
                    reader.read_bytes(buffer_len as usize)?,
                );
                let checksum: [u8; 32] =
                    reader.read_bytes(32)?.as_slice().try_into()?;
                *self = Self::Embedded {
                    name,
                    mime,
                    buffer,
                    checksum,
                };
            }
            EXTERNAL_FILE => {
                let name = reader.read_string()?;
                let mime = reader.read_string()?;
                let checksum: [u8; 32] =
                    reader.read_bytes(32)?.as_slice().try_into()?;
                let size = reader.read_u64()?;
                *self = Self::External {
                    name,
                    mime,
                    checksum,
                    size,
                    path: None,
                };
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownFileContentType(kind),
                )))
            }
        }
        Ok(())
    }
}

impl Encode for Secret {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let kind: u8 = self.kind().into();
        writer.write_u8(kind)?;

        match self {
            Self::Account {
                account,
                password,
                url,
                user_data,
            } => {
                writer.write_string(account)?;
                writer.write_string(password.expose_secret())?;
                writer.write_bool(url.is_some())?;
                if let Some(url) = url {
                    writer.write_string(url)?;
                }
                write_user_data(user_data, writer)?;
            }
            Self::Note { text, user_data } => {
                writer.write_string(text.expose_secret())?;
                write_user_data(user_data, writer)?;
            }
            Self::File {
                content, user_data, ..
            } => {
                content.encode(&mut *writer)?;
                write_user_data(user_data, writer)?;
            }
            Self::List { items, user_data } => {
                writer.write_u32(items.len() as u32)?;
                for (k, v) in items {
                    writer.write_string(k)?;
                    writer.write_string(v.expose_secret())?;
                }
                write_user_data(user_data, writer)?;
            }
            Self::Pem {
                certificates,
                user_data,
            } => {
                let value = pem::encode_many(certificates);
                writer.write_string(value)?;
                write_user_data(user_data, writer)?;
            }
            Self::Page {
                title,
                mime,
                document,
                user_data,
            } => {
                writer.write_string(title)?;
                writer.write_string(mime)?;
                writer.write_string(document.expose_secret())?;
                write_user_data(user_data, writer)?;
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
                writer.write_u8(id_kind)?;
                writer.write_string(number.expose_secret())?;

                writer.write_bool(issue_place.is_some())?;
                if let Some(issue_place) = issue_place {
                    writer.write_string(issue_place)?;
                }

                writer.write_bool(issue_date.is_some())?;
                if let Some(issue_date) = issue_date {
                    issue_date.encode(writer)?;
                }

                writer.write_bool(expiry_date.is_some())?;
                if let Some(expiry_date) = expiry_date {
                    expiry_date.encode(writer)?;
                }

                write_user_data(user_data, writer)?;
            }
            Self::Signer {
                private_key,
                user_data,
            } => {
                private_key.encode(writer)?;
                write_user_data(user_data, writer)?;
            }
            Self::Contact { vcard, user_data } => {
                writer.write_string(vcard.to_string())?;
                write_user_data(user_data, writer)?;
            }
            Self::Totp { totp, user_data } => {
                let totp = serde_json::to_vec(totp).map_err(Box::from)?;
                writer.write_u32(totp.len() as u32)?;
                writer.write_bytes(totp)?;
                write_user_data(user_data, writer)?;
            }
            Self::Card {
                number,
                expiry,
                cvv,
                name,
                atm_pin,
                user_data,
            } => {
                writer.write_string(number.expose_secret())?;

                writer.write_bool(expiry.is_some())?;
                if let Some(expiry) = expiry {
                    expiry.encode(&mut *writer)?;
                }
                writer.write_string(cvv.expose_secret())?;

                writer.write_bool(name.is_some())?;
                if let Some(name) = name {
                    writer.write_string(name.expose_secret())?;
                }

                writer.write_bool(atm_pin.is_some())?;
                if let Some(atm_pin) = atm_pin {
                    writer.write_string(atm_pin.expose_secret())?;
                }
                write_user_data(user_data, writer)?;
            }
            Self::Bank {
                number,
                routing,
                iban,
                swift,
                bic,
                user_data,
            } => {
                writer.write_string(number.expose_secret())?;
                writer.write_string(routing.expose_secret())?;

                writer.write_bool(iban.is_some())?;
                if let Some(iban) = iban {
                    writer.write_string(iban.expose_secret())?;
                }

                writer.write_bool(swift.is_some())?;
                if let Some(swift) = swift {
                    writer.write_string(swift.expose_secret())?;
                }

                writer.write_bool(bic.is_some())?;
                if let Some(bic) = bic {
                    writer.write_string(bic.expose_secret())?;
                }
                write_user_data(user_data, writer)?;
            }
            Self::Link {
                url,
                label,
                title,
                user_data,
            } => {
                writer.write_string(url.expose_secret())?;

                writer.write_bool(label.is_some())?;
                if let Some(label) = label {
                    writer.write_string(label.expose_secret())?;
                }

                writer.write_bool(title.is_some())?;
                if let Some(title) = title {
                    writer.write_string(title.expose_secret())?;
                }

                write_user_data(user_data, writer)?;
            }
            Self::Password {
                password,
                name,
                user_data,
            } => {
                writer.write_string(password.expose_secret())?;

                writer.write_bool(name.is_some())?;
                if let Some(name) = name {
                    writer.write_string(name.expose_secret())?;
                }

                write_user_data(user_data, writer)?;
            }
            Self::Age {
                version,
                key,
                user_data,
            } => {
                version.encode(writer)?;
                writer.write_string(key.expose_secret())?;
                write_user_data(user_data, writer)?;
            }
        }
        Ok(())
    }
}

impl Decode for Secret {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let kind: SecretType =
            reader.read_u8()?.try_into().map_err(Box::from)?;
        match kind {
            SecretType::Note => {
                let text = reader.read_string()?;
                let user_data = read_user_data(reader)?;
                *self = Self::Note {
                    text: secrecy::Secret::new(text),
                    user_data,
                };
            }
            SecretType::File => {
                let mut content: FileContent = Default::default();
                content.decode(&mut *reader)?;
                let user_data = read_user_data(reader)?;
                *self = Self::File { content, user_data };
            }
            SecretType::Account => {
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
                let user_data = read_user_data(reader)?;

                *self = Self::Account {
                    account,
                    password,
                    url,
                    user_data,
                };
            }
            SecretType::List => {
                let items_len = reader.read_u32()?;
                let mut items = HashMap::with_capacity(items_len as usize);
                for _ in 0..items_len {
                    let key = reader.read_string()?;
                    let value = secrecy::Secret::new(reader.read_string()?);
                    items.insert(key, value);
                }
                let user_data = read_user_data(reader)?;
                *self = Self::List { items, user_data };
            }
            SecretType::Pem => {
                let value = reader.read_string()?;
                let user_data = read_user_data(reader)?;
                *self = Self::Pem {
                    certificates: pem::parse_many(value)
                        .map_err(Box::from)?,
                    user_data,
                };
            }
            SecretType::Page => {
                let title = reader.read_string()?;
                let mime = reader.read_string()?;
                let document = secrecy::Secret::new(reader.read_string()?);
                let user_data = read_user_data(reader)?;
                *self = Self::Page {
                    title,
                    mime,
                    document,
                    user_data,
                };
            }
            SecretType::Identity => {
                let id_kind = reader.read_u8()?;
                let id_kind: IdentityKind =
                    id_kind.try_into().map_err(Box::from)?;

                let number = SecretString::new(reader.read_string()?);

                let has_issue_place = reader.read_bool()?;
                let issue_place = if has_issue_place {
                    Some(reader.read_string()?)
                } else {
                    None
                };

                let has_issue_date = reader.read_bool()?;
                let issue_date = if has_issue_date {
                    let mut timestamp: Timestamp = Default::default();
                    timestamp.decode(&mut *reader)?;
                    Some(timestamp)
                } else {
                    None
                };

                let has_expiry_date = reader.read_bool()?;
                let expiry_date = if has_expiry_date {
                    let mut timestamp: Timestamp = Default::default();
                    timestamp.decode(&mut *reader)?;
                    Some(timestamp)
                } else {
                    None
                };

                let user_data = read_user_data(reader)?;
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
                private_key.decode(reader)?;
                let user_data = read_user_data(reader)?;
                *self = Self::Signer {
                    private_key,
                    user_data,
                };
            }
            SecretType::Contact => {
                let vcard = reader.read_string()?;
                let mut cards = vcard4::parse(vcard).map_err(Box::from)?;
                let vcard = cards.remove(0);
                let user_data = read_user_data(reader)?;
                *self = Self::Contact {
                    vcard: Box::new(vcard),
                    user_data,
                };
            }
            SecretType::Totp => {
                let buffer_len = reader.read_u32()?;
                let buffer = reader.read_bytes(buffer_len as usize)?;
                let totp: TOTP =
                    serde_json::from_slice(&buffer).map_err(Box::from)?;
                let user_data = read_user_data(reader)?;
                *self = Self::Totp { totp, user_data };
            }
            SecretType::Card => {
                let number = SecretString::new(reader.read_string()?);
                let has_expiry = reader.read_bool()?;
                let expiry = if has_expiry {
                    let mut expiry: Timestamp = Default::default();
                    expiry.decode(reader)?;
                    Some(expiry)
                } else {
                    None
                };
                let cvv = SecretString::new(reader.read_string()?);

                let has_name = reader.read_bool()?;
                let name = if has_name {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let has_atm_pin = reader.read_bool()?;
                let atm_pin = if has_atm_pin {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let user_data = read_user_data(reader)?;
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
                let number = SecretString::new(reader.read_string()?);
                let routing = SecretString::new(reader.read_string()?);

                let has_iban = reader.read_bool()?;
                let iban = if has_iban {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let has_swift = reader.read_bool()?;
                let swift = if has_swift {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let has_bic = reader.read_bool()?;
                let bic = if has_bic {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let user_data = read_user_data(reader)?;
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
                let url = SecretString::new(reader.read_string()?);

                let has_label = reader.read_bool()?;
                let label = if has_label {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let has_title = reader.read_bool()?;
                let title = if has_title {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let user_data = read_user_data(reader)?;
                *self = Self::Link {
                    url,
                    label,
                    title,
                    user_data,
                };
            }
            SecretType::Password => {
                let password = SecretString::new(reader.read_string()?);

                let has_name = reader.read_bool()?;
                let name = if has_name {
                    Some(SecretString::new(reader.read_string()?))
                } else {
                    None
                };

                let user_data = read_user_data(reader)?;
                *self = Self::Password {
                    password,
                    name,
                    user_data,
                };
            }
            SecretType::Age => {
                let mut version: AgeVersion = Default::default();
                version.decode(reader)?;
                let key = SecretString::new(reader.read_string()?);

                let user_data = read_user_data(reader)?;
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
