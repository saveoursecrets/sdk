include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::{Error, Result};
use sos_net::sdk::{
    prelude::{
        ArchiveFilter, Document, DocumentView, ExtraFields, QueryFilter,
        SecretFlags, SecretMeta, SecretType,
    },
    vcard4::property::Kind as ContactKind,
    Error as SdkError, UtcDateTime,
};

impl From<DocumentView> for WireDocumentView {
    fn from(value: DocumentView) -> Self {
        todo!();
    }
}

impl TryFrom<WireDocumentView> for DocumentView {
    type Error = Error;
    fn try_from(value: WireDocumentView) -> Result<Self> {
        todo!();
    }
}

impl From<SecretType> for WireSecretType {
    fn from(value: SecretType) -> Self {
        match value {
            SecretType::Note => {
                WireSecretType::from_str_name("Note").unwrap()
            }
            SecretType::File => {
                WireSecretType::from_str_name("File").unwrap()
            }
            SecretType::Account => {
                WireSecretType::from_str_name("Account").unwrap()
            }
            SecretType::List => {
                WireSecretType::from_str_name("List").unwrap()
            }
            SecretType::Pem => WireSecretType::from_str_name("Pem").unwrap(),
            SecretType::Page => {
                WireSecretType::from_str_name("Page").unwrap()
            }
            SecretType::Signer => {
                WireSecretType::from_str_name("Signer").unwrap()
            }
            SecretType::Contact => {
                WireSecretType::from_str_name("Contact").unwrap()
            }
            SecretType::Totp => {
                WireSecretType::from_str_name("Totp").unwrap()
            }
            SecretType::Card => {
                WireSecretType::from_str_name("Card").unwrap()
            }
            SecretType::Bank => {
                WireSecretType::from_str_name("Bank").unwrap()
            }
            SecretType::Link => {
                WireSecretType::from_str_name("Link").unwrap()
            }
            SecretType::Password => {
                WireSecretType::from_str_name("Password").unwrap()
            }
            SecretType::Identity => {
                WireSecretType::from_str_name("Identity").unwrap()
            }
            SecretType::Age => WireSecretType::from_str_name("Age").unwrap(),
        }
    }
}

impl TryFrom<WireSecretType> for SecretType {
    type Error = Error;
    fn try_from(value: WireSecretType) -> Result<Self> {
        let name = value.as_str_name();
        Ok(match name {
            "Note" => SecretType::Note,
            "File" => SecretType::File,
            "Account" => SecretType::Account,
            "List" => SecretType::List,
            "Pem" => SecretType::Pem,
            "Page" => SecretType::Page,
            "Signer" => SecretType::Signer,
            "Contact" => SecretType::Contact,
            "Totp" => SecretType::Totp,
            "Card" => SecretType::Card,
            "Bank" => SecretType::Bank,
            "Link" => SecretType::Link,
            "Password" => SecretType::Password,
            "Identity" => SecretType::Identity,
            "Age" => SecretType::Age,
            _ => unreachable!(),
        })
    }
}

impl From<ContactKind> for WireContactKind {
    fn from(value: ContactKind) -> Self {
        match value {
            ContactKind::Individual => {
                WireContactKind::from_str_name("Individual").unwrap()
            }
            ContactKind::Group => {
                WireContactKind::from_str_name("Group").unwrap()
            }
            ContactKind::Org => {
                WireContactKind::from_str_name("Org").unwrap()
            }
            ContactKind::Location => {
                WireContactKind::from_str_name("Location").unwrap()
            }
        }
    }
}

impl TryFrom<WireContactKind> for ContactKind {
    type Error = Error;
    fn try_from(value: WireContactKind) -> Result<Self> {
        let name = value.as_str_name();
        Ok(match name {
            "Individual" => ContactKind::Individual,
            "Group" => ContactKind::Group,
            "Org" => ContactKind::Org,
            "Location" => ContactKind::Location,
            _ => unreachable!(),
        })
    }
}

impl From<QueryFilter> for WireQueryFilter {
    fn from(value: QueryFilter) -> Self {
        let mut types = Vec::with_capacity(value.types.len());
        for secret_type in value.types {
            types.push(WireSecretType::from(secret_type) as i32);
        }
        WireQueryFilter {
            tags: value.tags,
            folders: value
                .folders
                .into_iter()
                .map(|f| f.to_string())
                .collect(),
            types,
        }
    }
}

impl TryFrom<WireQueryFilter> for QueryFilter {
    type Error = Error;
    fn try_from(value: WireQueryFilter) -> Result<Self> {
        let mut folders = Vec::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.push(folder.parse().map_err(SdkError::from)?);
        }

        let mut types = Vec::with_capacity(value.types.len());
        for secret_type in value.types {
            let secret_type: WireSecretType = secret_type.try_into()?;
            types.push(secret_type.try_into()?);
        }

        Ok(QueryFilter {
            tags: value.tags,
            folders,
            types,
        })
    }
}

impl From<ArchiveFilter> for WireArchiveFilter {
    fn from(value: ArchiveFilter) -> Self {
        WireArchiveFilter {
            id: value.id.to_string(),
            include_documents: value.include_documents,
        }
    }
}

impl TryFrom<WireArchiveFilter> for ArchiveFilter {
    type Error = Error;
    fn try_from(value: WireArchiveFilter) -> Result<Self> {
        Ok(ArchiveFilter {
            id: value.id.parse().map_err(SdkError::from)?,
            include_documents: value.include_documents,
        })
    }
}

impl From<ExtraFields> for WireExtraFields {
    fn from(value: ExtraFields) -> Self {
        WireExtraFields {
            comment: value.comment,
            contact_type: value
                .contact_type
                .map(|v| WireContactKind::from(v) as i32),
        }
    }
}

impl TryFrom<WireExtraFields> for ExtraFields {
    type Error = Error;
    fn try_from(value: WireExtraFields) -> Result<Self> {
        let contact_type = if let Some(contact_type) = value.contact_type {
            let contact_type: WireContactKind = contact_type.try_into()?;
            Some(contact_type.try_into()?)
        } else {
            None
        };
        Ok(ExtraFields {
            comment: value.comment,
            contact_type,
        })
    }
}

/*
  // An optional owner identifier.
  optional string owner_id = 7;
  // Date created timestamp.
  string date_created = 8;
  // Last updated timestamp.
  string last_updated = 9;
*/

impl From<SecretMeta> for WireSecretMeta {
    fn from(value: SecretMeta) -> Self {
        let kind: WireSecretType = value.kind().clone().into();
        WireSecretMeta {
            kind: kind as i32,
            flags: value.flags().bits(),
            label: value.label().to_string(),
            tags: value.tags().into_iter().map(|t| t.to_owned()).collect(),
            favorite: value.favorite(),
            urn: value.urn().map(|u| u.to_string()),
            owner_id: value.owner_id().cloned(),
            date_created: value
                .date_created()
                .to_rfc3339()
                .ok()
                .unwrap_or_default(),
            last_updated: value
                .last_updated()
                .to_rfc3339()
                .ok()
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<WireSecretMeta> for SecretMeta {
    type Error = Error;
    fn try_from(value: WireSecretMeta) -> Result<Self> {
        let kind: WireSecretType = value.kind.try_into()?;
        let flags = SecretFlags::from_bits(value.flags).unwrap_or_default();
        let urn = if let Some(urn) = value.urn {
            Some(urn.parse().map_err(SdkError::from)?)
        } else {
            None
        };
        let owner_id = if let Some(owner_id) = value.owner_id {
            Some(owner_id)
        } else {
            None
        };
        let date_created = UtcDateTime::parse_rfc3339(&value.date_created)
            .map_err(SdkError::from)?;
        let last_updated = UtcDateTime::parse_rfc3339(&value.last_updated)
            .map_err(SdkError::from)?;

        let mut meta = SecretMeta::new(value.label, kind.try_into()?);
        *meta.flags_mut() = flags;
        meta.set_tags(value.tags.into_iter().collect());
        meta.set_favorite(value.favorite);
        meta.set_urn(urn);
        meta.set_owner_id(owner_id);
        meta.set_date_created(date_created);
        meta.set_last_updated(last_updated);
        Ok(meta)
    }
}

impl From<Document> for WireDocument {
    fn from(value: Document) -> Self {
        WireDocument {
            vault_id: value.vault_id.to_string(),
            secret_id: value.secret_id.to_string(),
            meta: Some(value.meta.into()),
            extra: Some(value.extra.into()),
        }
    }
}

impl TryFrom<WireDocument> for Document {
    type Error = Error;
    fn try_from(value: WireDocument) -> Result<Self> {
        let meta = value.meta.unwrap();
        let extra = value.extra.unwrap();
        Ok(Document {
            vault_id: value.vault_id.parse().map_err(SdkError::from)?,
            secret_id: value.secret_id.parse().map_err(SdkError::from)?,
            meta: meta.try_into()?,
            extra: extra.try_into()?,
        })
    }
}
