include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::{Error, Result};
use sos_net::{
    protocol::local_transport::{LocalRequest, LocalResponse},
    sdk::{
        prelude::{
            Address, ArchiveFilter, Document, DocumentView, ExtraFields,
            PublicIdentity, QualifiedPath, QueryFilter, SecretFlags,
            SecretMeta, SecretType,
        },
        url::Url,
        urn::Urn,
        vcard4::property::Kind as ContactKind,
        Error as SdkError, UtcDateTime,
    },
};
use std::collections::HashMap;

impl From<DocumentView> for WireDocumentView {
    fn from(value: DocumentView) -> Self {
        match value {
            DocumentView::All { ignored_types } => WireDocumentView {
                inner: Some(wire_document_view::Inner::All(
                    WireDocumentViewAll {
                        ignored_types: ignored_types
                            .unwrap_or_default()
                            .into_iter()
                            .map(|t| WireSecretType::from(t) as i32)
                            .collect(),
                    },
                )),
            },
            DocumentView::Vault(folder_id) => WireDocumentView {
                inner: Some(wire_document_view::Inner::Vault(
                    WireDocumentViewVault {
                        folder_id: folder_id.to_string(),
                    },
                )),
            },
            DocumentView::TypeId(secret_type) => {
                let secret_type = WireSecretType::from(secret_type) as i32;
                WireDocumentView {
                    inner: Some(wire_document_view::Inner::TypeId(
                        secret_type,
                    )),
                }
            }
            DocumentView::Favorites => WireDocumentView {
                inner: Some(wire_document_view::Inner::Favorites(
                    WireVoidBody {},
                )),
            },
            DocumentView::Tags(tags) => WireDocumentView {
                inner: Some(wire_document_view::Inner::Tags(
                    WireDocumentViewTags { list: tags },
                )),
            },
            DocumentView::Contact { include_types } => WireDocumentView {
                inner: Some(wire_document_view::Inner::Contact(
                    WireDocumentViewContact {
                        include_types: include_types
                            .unwrap_or_default()
                            .into_iter()
                            .map(|t| WireContactKind::from(t) as i32)
                            .collect(),
                    },
                )),
            },
            DocumentView::Documents {
                folder_id,
                identifiers,
            } => WireDocumentView {
                inner: Some(wire_document_view::Inner::Documents(
                    WireDocumentViewDocuments {
                        folder_id: folder_id.to_string(),
                        identifiers: identifiers
                            .into_iter()
                            .map(|i| i.to_string())
                            .collect(),
                    },
                )),
            },
            DocumentView::Websites { matches, exact } => WireDocumentView {
                inner: Some(wire_document_view::Inner::Websites(
                    WireDocumentViewWebsites {
                        matches: if let Some(matches) = matches {
                            matches
                                .into_iter()
                                .map(|u| u.to_string())
                                .collect()
                        } else {
                            vec![]
                        },
                        exact,
                    },
                )),
            },
        }
    }
}

impl TryFrom<WireDocumentView> for DocumentView {
    type Error = Error;
    fn try_from(value: WireDocumentView) -> Result<Self> {
        Ok(match value.inner {
            Some(wire_document_view::Inner::All(body)) => {
                let ignored_types = if !body.ignored_types.is_empty() {
                    let mut ignored_types =
                        Vec::with_capacity(body.ignored_types.len());
                    for secret_type in body.ignored_types {
                        let secret_type: WireSecretType =
                            secret_type.try_into()?;
                        ignored_types.push(secret_type.try_into()?);
                    }
                    Some(ignored_types)
                } else {
                    None
                };
                DocumentView::All { ignored_types }
            }
            Some(wire_document_view::Inner::Vault(body)) => {
                DocumentView::Vault(
                    body.folder_id.parse().map_err(SdkError::from)?,
                )
            }
            Some(wire_document_view::Inner::TypeId(body)) => {
                let secret_type: WireSecretType = body.try_into()?;
                let secret_type: SecretType = secret_type.try_into()?;
                DocumentView::TypeId(secret_type)
            }
            Some(wire_document_view::Inner::Favorites(_)) => {
                DocumentView::Favorites
            }
            Some(wire_document_view::Inner::Tags(body)) => {
                DocumentView::Tags(body.list)
            }
            Some(wire_document_view::Inner::Contact(body)) => {
                let include_types = if !body.include_types.is_empty() {
                    let mut include_types =
                        Vec::with_capacity(body.include_types.len());
                    for contact_type in body.include_types {
                        let contact_type: WireContactKind =
                            contact_type.try_into()?;
                        include_types.push(contact_type.try_into()?);
                    }
                    Some(include_types)
                } else {
                    None
                };
                DocumentView::Contact { include_types }
            }
            Some(wire_document_view::Inner::Documents(body)) => {
                let mut identifiers =
                    Vec::with_capacity(body.identifiers.len());
                for id in body.identifiers {
                    identifiers.push(id.parse().map_err(SdkError::from)?);
                }

                DocumentView::Documents {
                    folder_id: body
                        .folder_id
                        .parse()
                        .map_err(SdkError::from)?,
                    identifiers,
                }
            }
            Some(wire_document_view::Inner::Websites(body)) => {
                let matches = if !body.matches.is_empty() {
                    let mut matches: Vec<Url> =
                        Vec::with_capacity(body.matches.len());
                    for target in body.matches {
                        matches.push(target.parse().map_err(SdkError::from)?);
                    }
                    Some(matches)
                } else {
                    None
                };

                DocumentView::Websites {
                    matches,
                    exact: body.exact,
                }
            }
            _ => unreachable!("unknown document view variant"),
        })
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
            _ => unreachable!("unknown secret type variant"),
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
            _ => unreachable!("unknown contact type variant"),
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
            websites: value.websites.unwrap_or_default(),
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
            websites: if value.websites.is_empty() {
                None
            } else {
                Some(value.websites)
            },
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
            folder_id: value.folder_id.to_string(),
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
            folder_id: value.folder_id.parse().map_err(SdkError::from)?,
            secret_id: value.secret_id.parse().map_err(SdkError::from)?,
            meta: meta.try_into()?,
            extra: extra.try_into()?,
        })
    }
}

impl From<PublicIdentity> for WirePublicIdentity {
    fn from(value: PublicIdentity) -> Self {
        WirePublicIdentity {
            address: value.address().to_string(),
            label: value.label().to_owned(),
        }
    }
}

impl TryFrom<WirePublicIdentity> for PublicIdentity {
    type Error = Error;
    fn try_from(value: WirePublicIdentity) -> Result<Self> {
        let address: Address = value.address.parse()?;
        Ok(PublicIdentity::new(value.label, address))
    }
}

impl From<QualifiedPath> for WireQualifiedPath {
    fn from(value: QualifiedPath) -> Self {
        let urn: Urn = value.try_into().unwrap();
        WireQualifiedPath {
            urn: urn.to_string(),
        }
    }
}

impl TryFrom<WireQualifiedPath> for QualifiedPath {
    type Error = sos_net::sdk::Error;
    fn try_from(
        value: WireQualifiedPath,
    ) -> std::result::Result<Self, Self::Error> {
        let urn: Urn = value.urn.parse()?;
        Ok(urn.try_into()?)
    }
}

impl From<LocalRequest> for WireLocalRequest {
    fn from(value: LocalRequest) -> Self {
        WireLocalRequest {
            uri: value.uri.to_string(),
            method: value.method.to_string(),
            headers: value
                .headers
                .into_iter()
                .map(|(k, v)| WireTransportHeader { name: k, values: v })
                .collect(),
            body: value.body,
        }
    }
}

impl TryFrom<WireLocalRequest> for LocalRequest {
    type Error = Error;

    fn try_from(value: WireLocalRequest) -> Result<Self> {
        let mut headers = HashMap::new();
        for mut header in value.headers {
            let entry = headers.entry(header.name).or_insert(vec![]);
            entry.append(&mut header.values);
        }

        Ok(Self {
            uri: value.uri.parse()?,
            method: value.method.parse()?,
            headers,
            body: value.body,
        })
    }
}

impl From<LocalResponse> for WireLocalResponse {
    fn from(value: LocalResponse) -> Self {
        let status: u16 = value.status().into();
        WireLocalResponse {
            status: status.into(),
            headers: value
                .headers
                .into_iter()
                .map(|(k, v)| WireTransportHeader { name: k, values: v })
                .collect(),
            body: value.body,
        }
    }
}

impl TryFrom<WireLocalResponse> for LocalResponse {
    type Error = Error;

    fn try_from(value: WireLocalResponse) -> Result<Self> {
        let status: u16 = value.status.try_into()?;

        let mut headers = HashMap::new();
        for mut header in value.headers {
            let entry = headers.entry(header.name).or_insert(vec![]);
            entry.append(&mut header.values);
        }

        Ok(Self {
            status: status.try_into()?,
            headers,
            body: value.body,
        })
    }
}
