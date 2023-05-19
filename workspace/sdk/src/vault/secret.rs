//! Types used to represent vault meta data and secrets.
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use bitflags::bitflags;
use ed25519_dalek::SECRET_KEY_LENGTH;
use pem::Pem;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{
    de::{self, Deserializer, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Serialize, Serializer,
};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
    str::FromStr,
};
use totp_sos::TOTP;
use url::Url;
use urn::Urn;
use uuid::Uuid;
use vcard4::{self, Vcard};

use crate::{
    signer::{
        ecdsa::{self, BoxedEcdsaSigner},
        ed25519::{self, BoxedEd25519Signer},
    },
    storage::{basename, guess_mime},
    Error, Result, Timestamp,
};

const EMBEDDED_FILE: u8 = 1;
const EXTERNAL_FILE: u8 = 2;

/// Secret with meta data and possibly an identifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// Secret identifier.
    pub id: Option<SecretId>,
    /// Secret meta data.
    pub meta: SecretMeta,
    /// Secret information.
    pub secret: Secret,
}

bitflags! {
    /// Bit flags for a secret.
    #[derive(Default, Serialize, Deserialize)]
    pub struct SecretFlags: u32 {
        /// Clients should verify the account passphrase
        /// before revealing this secret.
        const VERIFY            =        0b00000001;
    }
}

impl SecretFlags {
    /// Determine if this secret requires verification to access.
    pub fn must_verify(&self) -> bool {
        self.contains(SecretFlags::VERIFY)
    }
}

fn serialize_secret_string<S>(
    secret: &SecretString,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(secret.expose_secret())
}

fn serialize_secret_option<S>(
    secret: &Option<SecretString>,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(ref value) => ser.serialize_some(value.expose_secret()),
        None => ser.serialize_none(),
    }
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

fn is_empty_secret_vec(value: &SecretVec<u8>) -> bool {
    value.expose_secret().is_empty()
}

fn default_secret_vec() -> SecretVec<u8> {
    SecretVec::new(Vec::new())
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

impl From<SecretId> for SecretRef {
    fn from(value: SecretId) -> Self {
        Self::Id(value)
    }
}

impl From<String> for SecretRef {
    fn from(value: String) -> Self {
        Self::Name(value)
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

/// Type of secret assigned to the secret meta data.
///
/// Matches the enum variants for a secret and is used
/// so we can know the type of secret from the meta data
/// before secret data has been decrypted.
#[derive(
    Default, Clone, Debug, Copy, Serialize, Deserialize, Eq, PartialEq, Hash,
)]
#[serde(rename_all = "lowercase")]
pub enum SecretType {
    /// UTF-8 encoded note.
    #[default]
    Note,
    /// Binary blob.
    File,
    /// Account with login password.
    Account,
    /// Collection of credentials as key/value pairs.
    List,
    /// PEM encoded binary data.
    Pem,
    /// UTF-8 text document.
    Page,
    /// Private signing key.
    Signer,
    /// Contact for an organization, person, group or location.
    Contact,
    /// Two-factor authentication using a TOTP.
    Totp,
    /// Credit or debit card.
    Card,
    /// Bank account.
    Bank,
    /// External link; intended to be used in embedded user fields.
    Link,
    /// Standalone password; intended to be used in embedded user fields.
    Password,
    /// Identity secret for passports, driving licenses etc.
    Identity,
    /// AGE encryption standard.
    Age,
}

impl SecretType {
    /// Get an abbreviated short name.
    pub fn short_name(&self) -> &str {
        match self {
            Self::Note => "note",
            Self::File => "file",
            Self::Account => "acct",
            Self::List => "list",
            Self::Pem => "cert",
            Self::Page => "page",
            Self::Identity => "iden",
            Self::Signer => "sign",
            Self::Contact => "cont",
            Self::Totp => "totp",
            Self::Card => "card",
            Self::Bank => "bank",
            Self::Link => "link",
            Self::Password => "pass",
            Self::Age => "age",
        }
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Note => "Note",
                Self::File => "File",
                Self::Account => "Account",
                Self::List => "List",
                Self::Pem => "Certificate",
                Self::Page => "Page",
                Self::Identity => "Identity",
                Self::Signer => "Signer",
                Self::Contact => "Contact",
                Self::Totp => "Authenticator",
                Self::Card => "Card",
                Self::Bank => "Bank",
                Self::Link => "Link",
                Self::Password => "Password",
                Self::Age => "Age",
            }
        )
    }
}

impl From<&SecretType> for u8 {
    fn from(value: &SecretType) -> Self {
        match value {
            SecretType::Note => kind::NOTE,
            SecretType::File => kind::FILE,
            SecretType::Account => kind::ACCOUNT,
            SecretType::List => kind::LIST,
            SecretType::Pem => kind::PEM,
            SecretType::Page => kind::PAGE,
            SecretType::Identity => kind::IDENTIFICATION,
            SecretType::Signer => kind::SIGNER,
            SecretType::Contact => kind::CONTACT,
            SecretType::Totp => kind::TOTP,
            SecretType::Card => kind::CARD,
            SecretType::Bank => kind::BANK,
            SecretType::Link => kind::LINK,
            SecretType::Password => kind::PASSWORD,
            SecretType::Age => kind::AGE,
        }
    }
}

impl From<SecretType> for u8 {
    fn from(value: SecretType) -> Self {
        (&value).into()
    }
}

impl TryFrom<u8> for SecretType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            kind::NOTE => Self::Note,
            kind::FILE => Self::File,
            kind::ACCOUNT => Self::Account,
            kind::LIST => Self::List,
            kind::PEM => Self::Pem,
            kind::PAGE => Self::Page,
            kind::IDENTIFICATION => Self::Identity,
            kind::SIGNER => Self::Signer,
            kind::CONTACT => Self::Contact,
            kind::TOTP => Self::Totp,
            kind::CARD => Self::Card,
            kind::BANK => Self::Bank,
            kind::LINK => Self::Link,
            kind::PASSWORD => Self::Password,
            kind::AGE => Self::Age,
            _ => return Err(Error::UnknownSecretKind(value)),
        })
    }
}

/// Encapsulates the meta data for a secret.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    /// Kind of the secret.
    kind: SecretType,
    /// Flags for the secret.
    flags: SecretFlags,
    /// Human-friendly label for the secret.
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    /// Collection of tags.
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    tags: HashSet<String>,
    /// Whether this secret is a favorite.
    favorite: bool,
    /// A URN identifier for this secret.
    ///
    /// This is used when an identity vault stores passphrases
    /// for other vault folders on behalf of a user and can also
    /// be used to assign a predictable identifier for a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    urn: Option<Urn>,
    /// An optional owner identifier.
    ///
    /// This can be used when creating secrets on behalf of a
    /// third-party plugin or application to indicate the identifier
    /// of the third-party application.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    /// Date created timestamp.
    date_created: Timestamp,
    /// Last updated timestamp.
    #[serde(skip_deserializing)]
    last_updated: Timestamp,
}

impl fmt::Display for SecretMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}", self.kind, self.label)?;
        if let Some(urn) = &self.urn {
            writeln!(f, "{}", urn)?;
        }
        writeln!(f)?;

        if !self.tags.is_empty() {
            let mut list = Vec::new();
            for tag in &self.tags {
                list.push(&tag[..]);
            }
            list.sort();
            let tags = list.join(", ");
            writeln!(f, "Tags: {}", tags)?;
        }
        writeln!(
            f,
            "Favorite: {}",
            if self.favorite { "yes" } else { "no" }
        )?;

        writeln!(f)?;
        writeln!(f, "Created: {}", self.date_created)?;
        write!(f, "Updated: {}", self.last_updated)
    }
}

impl PartialEq for SecretMeta {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.label == other.label
            && self.urn == other.urn
    }
}

impl Eq for SecretMeta {}

impl PartialOrd for SecretMeta {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.label.partial_cmp(&other.label)
    }
}

impl SecretMeta {
    /// Create new meta data for a secret.
    pub fn new(label: String, kind: SecretType) -> Self {
        Self {
            kind,
            flags: Default::default(),
            label,
            date_created: Default::default(),
            last_updated: Default::default(),
            tags: Default::default(),
            urn: None,
            owner_id: None,
            favorite: false,
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
    pub fn kind(&self) -> &SecretType {
        &self.kind
    }

    /// The created date and time.
    pub fn date_created(&self) -> &Timestamp {
        &self.date_created
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

    /// Mutable tags reference.
    pub fn tags_mut(&mut self) -> &mut HashSet<String> {
        &mut self.tags
    }

    /// Get the URN for this secret.
    pub fn urn(&self) -> Option<&Urn> {
        self.urn.as_ref()
    }

    /// Set the URN for this secret.
    pub fn set_urn(&mut self, urn: Option<Urn>) {
        self.urn = urn;
    }

    /// Get the owner identifier for this secret.
    pub fn owner_id(&self) -> Option<&String> {
        self.owner_id.as_ref()
    }

    /// Set the owner identifier for this secret.
    pub fn set_owner_id(&mut self, owner_id: Option<String>) {
        self.owner_id = owner_id;
    }

    /// The favorite for the secret.
    pub fn favorite(&self) -> bool {
        self.favorite
    }

    /// Set the favorite for the secret.
    pub fn set_favorite(&mut self, favorite: bool) {
        self.favorite = favorite;
    }

    /// The flags for the secret.
    pub fn flags(&self) -> &SecretFlags {
        &self.flags
    }

    /// The mutable flags for the secret.
    pub fn flags_mut(&mut self) -> &mut SecretFlags {
        &mut self.flags
    }
}

impl Encode for SecretMeta {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
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
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
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

/// Constants for signer kinds.
mod signer_kind {
    pub(crate) const SINGLE_PARTY_ECDSA: u8 = 1;
    pub(crate) const SINGLE_PARTY_ED25519: u8 = 2;
}

/// Secret type that encapsulates a signing private key.
#[derive(Serialize, Deserialize)]
pub enum SecretSigner {
    /// Single party Ethereum-compatible ECDSA signing private key.
    #[serde(serialize_with = "serialize_secret_buffer")]
    SinglePartyEcdsa(SecretVec<u8>),
    /// Single party Ed25519 signing private key.
    #[serde(serialize_with = "serialize_secret_buffer")]
    SinglePartyEd25519(SecretVec<u8>),
}

impl From<ecdsa::SingleParty> for SecretSigner {
    fn from(value: ecdsa::SingleParty) -> Self {
        Self::SinglePartyEcdsa(SecretVec::new(value.0.to_bytes().to_vec()))
    }
}

impl From<ed25519::SingleParty> for SecretSigner {
    fn from(value: ed25519::SingleParty) -> Self {
        Self::SinglePartyEd25519(SecretVec::new(value.0.to_bytes().to_vec()))
    }
}

impl SecretSigner {
    /// Try to convert this signing key into an ECDSA signer.
    pub fn try_into_ecdsa_signer(self) -> Result<BoxedEcdsaSigner> {
        match self {
            Self::SinglePartyEcdsa(key) => {
                let private_key: [u8; 32] =
                    key.expose_secret().as_slice().try_into()?;
                let signer: ecdsa::SingleParty = private_key.try_into()?;
                Ok(Box::new(signer))
            }
            _ => Err(Error::NotEcdsaKey),
        }
    }

    /// Try to convert this signing key into an Ed25519 signer.
    pub fn try_into_ed25519_signer(self) -> Result<BoxedEd25519Signer> {
        match self {
            Self::SinglePartyEd25519(key) => {
                let keypair: [u8; SECRET_KEY_LENGTH] =
                    key.expose_secret().as_slice().try_into()?;
                let signer: ed25519::SingleParty = keypair.try_into()?;
                Ok(Box::new(signer))
            }
            _ => Err(Error::NotEd25519Key),
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
            Self::SinglePartyEd25519(buffer) => Self::SinglePartyEd25519(
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
            (Self::SinglePartyEd25519(a), Self::SinglePartyEd25519(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            _ => false,
        }
    }
}

impl Encode for SecretSigner {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
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

/// Secret with it's associated meta data and identifier.
#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SecretRow {
    /// Identifier for the secret.
    id: SecretId,
    /// Meta data for the secret.
    meta: SecretMeta,
    /// The data for the secret.
    secret: Secret,
}

impl SecretRow {
    /// Create a new secret row with known identifier.
    pub fn new(id: SecretId, meta: SecretMeta, secret: Secret) -> Self {
        Self { id, meta, secret }
    }

    /// Identifier for the row.
    pub fn id(&self) -> &SecretId {
        &self.id
    }

    /// Meta data for the secret.
    pub fn meta(&self) -> &SecretMeta {
        &self.meta
    }

    /// Mutable meta data for the secret.
    pub fn meta_mut(&mut self) -> &mut SecretMeta {
        &mut self.meta
    }

    /// Secret data.
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Mutable secret data.
    pub fn secret_mut(&mut self) -> &mut Secret {
        &mut self.secret
    }
}

impl From<SecretRow> for (SecretId, SecretMeta, Secret) {
    fn from(value: SecretRow) -> Self {
        (value.id, value.meta, value.secret)
    }
}

impl From<SecretRow> for Secret {
    fn from(value: SecretRow) -> Self {
        value.secret
    }
}

impl Encode for SecretRow {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(self.id.as_bytes())?;
        self.meta.encode(&mut *writer)?;
        self.secret.encode(&mut *writer)?;
        Ok(())
    }
}

impl Decode for SecretRow {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        self.id = Uuid::from_bytes(uuid);
        self.meta.decode(&mut *reader)?;
        self.secret.decode(&mut *reader)?;
        Ok(())
    }
}

/// Collection of custom user data.
#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UserData {
    /// Collection of custom user_data.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<SecretRow>,
    /// Comment for the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    /// Recovery notes.
    ///
    /// These are notes specific for a person that might recover
    /// the vault information and is intended to provide additional
    /// information on how to use this secret in the event of an
    /// emergency.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_note: Option<String>,
}

impl UserData {
    /// Create user data with a comment.
    pub fn new_comment(value: String) -> Self {
        Self {
            fields: Default::default(),
            comment: Some(value),
            recovery_note: Default::default(),
        }
    }

    /// Get the number of user data.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Determine of there are any user data fields.
    pub fn is_empty(&self) -> bool {
        self.len() == 0 && self.recovery_note.is_none()
    }

    /// Determine of there are any user data.
    pub fn is_default(&self) -> bool {
        self.is_empty() && self.recovery_note.is_none()
    }

    /// Get the user fields.
    pub fn fields(&self) -> &Vec<SecretRow> {
        &self.fields
    }

    /// Get a mutable reference to the user fields.
    pub fn fields_mut(&mut self) -> &mut Vec<SecretRow> {
        &mut self.fields
    }

    /// Add a custom field to this collection.
    pub fn push(&mut self, field: SecretRow) {
        self.fields.push(field);
    }

    /// Get the comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|s| &s[..])
    }

    /// Set the comment.
    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    /// Get the recovery notes.
    pub fn recovery_note(&self) -> Option<&str> {
        self.recovery_note.as_ref().map(|s| &s[..])
    }

    /// Set the recovery notes.
    pub fn set_recovery_note(&mut self, notes: Option<String>) {
        self.recovery_note = notes;
    }
}

fn write_user_data(
    user_data: &UserData,
    writer: &mut BinaryWriter,
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

fn read_user_data(reader: &mut BinaryReader) -> BinaryResult<UserData> {
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

/// Enumeration of types of identification.
#[derive(PartialEq, Eq, Clone)]
pub enum IdentityKind {
    /// Personal identification number (PIN).
    PersonalIdNumber,
    /// Generic id card.
    IdCard,
    /// Passport identification.
    Passport,
    ///  Driver license identification.
    DriverLicense,
    /// Social security identification.
    SocialSecurity,
    /// Tax number identification.
    TaxNumber,
    /// Medical card identification.
    MedicalCard,
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PersonalIdNumber => "PIN",
                Self::IdCard => "Id",
                Self::Passport => "Passport",
                Self::DriverLicense => "Driver license",
                Self::SocialSecurity => "Social security",
                Self::TaxNumber => "Tax number",
                Self::MedicalCard => "Medical card",
            }
        )
    }
}

impl From<IdentityKind> for u8 {
    fn from(value: IdentityKind) -> Self {
        (&value).into()
    }
}

impl From<&IdentityKind> for u8 {
    fn from(value: &IdentityKind) -> Self {
        match value {
            IdentityKind::PersonalIdNumber => 1,
            IdentityKind::IdCard => 2,
            IdentityKind::Passport => 3,
            IdentityKind::DriverLicense => 4,
            IdentityKind::SocialSecurity => 5,
            IdentityKind::TaxNumber => 6,
            IdentityKind::MedicalCard => 7,
        }
    }
}

impl TryFrom<u8> for IdentityKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(IdentityKind::PersonalIdNumber),
            2 => Ok(IdentityKind::IdCard),
            3 => Ok(IdentityKind::Passport),
            4 => Ok(IdentityKind::DriverLicense),
            5 => Ok(IdentityKind::SocialSecurity),
            6 => Ok(IdentityKind::TaxNumber),
            7 => Ok(IdentityKind::MedicalCard),
            _ => Err(Error::UnknownIdentityKind(value)),
        }
    }
}

impl Serialize for IdentityKind {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.into())
    }
}

impl<'de> Deserialize<'de> for IdentityKind {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<IdentityKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(IdentityKindVisitor)
    }
}

struct IdentityKindVisitor;

impl<'de> Visitor<'de> for IdentityKindVisitor {
    type Value = IdentityKind;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str("an integer between 0 and 255 for identification kind")
    }

    fn visit_u8<E>(self, value: u8) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        let value: IdentityKind = value.try_into().unwrap();
        Ok(value)
    }
}

/// Enumeration of AGE versions.
#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum AgeVersion {
    /// The v1 AGE version.
    #[default]
    Version1,
}

impl Encode for AgeVersion {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        match self {
            Self::Version1 => writer.write_u8(1)?,
        };
        Ok(())
    }
}

impl Decode for AgeVersion {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
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

/// Variants for embedded and external file secrets.
#[derive(Serialize, Deserialize)]
pub enum FileContent {
    /// Embedded file buffer.
    Embedded {
        /// File name.
        name: String,

        /// Mime type for the data.
        ///
        /// Use application/octet-stream if no mime-type is available.
        mime: String,

        /// The binary data.
        #[serde(
            default = "default_secret_vec",
            serialize_with = "serialize_secret_buffer",
            skip_serializing_if = "is_empty_secret_vec"
        )]
        buffer: SecretVec<u8>,

        /// The SHA-256 digest of the buffer.
        ///
        /// Using the SHA-256 digest allows the checksum to be computed
        /// using the Javascript SubtleCrypto API and in Dart using the
        /// crypto package.
        ///
        /// This is used primarily during the public migration export
        /// to identify files that have been extracted to another location
        /// in the archive rather than embedding the binary data.
        #[serde(with = "hex::serde")]
        checksum: [u8; 32],
    },
    /// Encrypted data is stored in an external file.
    External {
        /// File name.
        name: String,

        /// Mime type for the data.
        ///
        /// Use application/octet-stream if no mime-type is available.
        mime: String,

        /// The SHA-256 digest of the buffer.
        ///
        /// Using the SHA-256 digest allows the checksum to be computed
        /// using the Javascript SubtleCrypto API and in Dart using the
        /// crypto package.
        ///
        /// This is used primarily during the public migration export
        /// to identify files that have been extracted to another location
        /// in the archive rather than embedding the binary data.
        #[serde(with = "hex::serde")]
        checksum: [u8; 32],

        /// Size of the encrypted file content.
        size: u64,

        /// Optional path to a source file; never encoded or serialized.
        #[serde(skip)]
        path: Option<PathBuf>,
    },
}

impl FileContent {
    /// File name.
    pub fn name(&self) -> &str {
        match self {
            Self::Embedded { name, .. } => name,
            Self::External { name, .. } => name,
        }
    }

    /// File mime type.
    pub fn mime(&self) -> &str {
        match self {
            Self::Embedded { mime, .. } => mime,
            Self::External { mime, .. } => mime,
        }
    }

    /// File checksum.
    pub fn checksum(&self) -> &[u8; 32] {
        match self {
            Self::Embedded { checksum, .. } => checksum,
            Self::External { checksum, .. } => checksum,
        }
    }

    /// File size.
    pub fn size(&self) -> u64 {
        match self {
            Self::Embedded { buffer, .. } => {
                buffer.expose_secret().len() as u64
            }
            Self::External { size, .. } => *size,
        }
    }
}

impl Default for FileContent {
    fn default() -> Self {
        Self::Embedded {
            name: String::new(),
            mime: String::new(),
            buffer: SecretVec::new(vec![]),
            checksum: [0; 32],
        }
    }
}

impl PartialEq for FileContent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Embedded {
                    name: name_a,
                    mime: mime_a,
                    buffer: buffer_a,
                    checksum: checksum_a,
                },
                Self::Embedded {
                    name: name_b,
                    mime: mime_b,
                    buffer: buffer_b,
                    checksum: checksum_b,
                },
            ) => {
                name_a == name_b
                    && mime_a == mime_b
                    && buffer_a.expose_secret() == buffer_b.expose_secret()
                    && checksum_a == checksum_b
            }
            (
                Self::External {
                    name: name_a,
                    mime: mime_a,
                    checksum: checksum_a,
                    size: size_a,
                    path: path_a,
                },
                Self::External {
                    name: name_b,
                    mime: mime_b,
                    checksum: checksum_b,
                    size: size_b,
                    path: path_b,
                },
            ) => {
                name_a == name_b
                    && mime_a == mime_b
                    && checksum_a == checksum_b
                    && size_a == size_b
                    && path_a == path_b
            }
            _ => false,
        }
    }
}

impl Clone for FileContent {
    fn clone(&self) -> Self {
        match self {
            FileContent::Embedded {
                name,
                mime,
                buffer,
                checksum,
            } => FileContent::Embedded {
                name: name.to_owned(),
                mime: mime.to_owned(),
                buffer: secrecy::Secret::new(buffer.expose_secret().to_vec()),
                checksum: *checksum,
            },
            FileContent::External {
                name,
                mime,
                checksum,
                size,
                path,
            } => FileContent::External {
                name: name.to_owned(),
                mime: mime.to_owned(),
                checksum: *checksum,
                size: *size,
                path: path.clone(),
            },
        }
    }
}

impl Encode for FileContent {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
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
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
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

/// Represents the various types of secret.
///
/// Some variants can be created from other types
/// using a `From` or `TryFrom` implementation:
///
/// * `String`                              -> `Secret::Note`
/// * `HashMap<String, SecretString>`       -> `Secret::List`
/// * `SecretString`                        -> `Secret::Password`
/// * `PathBuf`                             -> `Secret::File`
/// * `Url`                                 -> `Secret::Link`
///
#[derive(Serialize, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum Secret {
    /// A UTF-8 encoded note.
    #[serde(rename_all = "camelCase")]
    Note {
        /// Note text.
        #[serde(serialize_with = "serialize_secret_string")]
        text: SecretString,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// A binary blob.
    #[serde(rename_all = "camelCase")]
    File {
        /// File secret data.
        content: FileContent,

        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Account with login password.
    #[serde(rename_all = "camelCase")]
    Account {
        /// Name of the account.
        account: String,
        /// Optional URL associated with the account.
        url: Option<Url>,
        /// The account password.
        #[serde(serialize_with = "serialize_secret_string")]
        password: SecretString,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Collection of credentials as key/value pairs.
    #[serde(rename_all = "camelCase")]
    List {
        /// The items in the list.
        #[serde(serialize_with = "serialize_secret_string_map")]
        items: HashMap<String, SecretString>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// PEM encoded binary data.
    #[serde(rename_all = "camelCase")]
    Pem {
        /// Collection of PEM encoded certificates or keys.
        certificates: Vec<Pem>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// A UTF-8 text document.
    #[serde(rename_all = "camelCase")]
    Page {
        /// Title of the page.
        title: String,
        /// Mime type for the text, default is `text/markdown`.
        mime: String,
        /// The binary data.
        #[serde(serialize_with = "serialize_secret_string")]
        document: SecretString,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Private signing key.
    #[serde(rename_all = "camelCase")]
    Signer {
        /// The private key.
        private_key: SecretSigner,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Contact for an organization or person.
    #[serde(rename_all = "camelCase")]
    Contact {
        /// The contact vCard.
        vcard: Box<Vcard>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Two-factor authentication using a TOTP.
    #[serde(rename_all = "camelCase")]
    Totp {
        /// Time-based one-time passcode.
        totp: TOTP,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Credit or debit card.
    #[serde(rename_all = "camelCase")]
    Card {
        /// The card number.
        #[serde(serialize_with = "serialize_secret_string")]
        number: SecretString,
        /// The expiry data for the card.
        expiry: Option<Timestamp>,
        /// Card verification value.
        #[serde(serialize_with = "serialize_secret_string")]
        cvv: SecretString,
        /// Name that appears on the card.
        #[serde(serialize_with = "serialize_secret_option")]
        name: Option<SecretString>,
        /// ATM PIN.
        #[serde(serialize_with = "serialize_secret_option")]
        atm_pin: Option<SecretString>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Bank account.
    #[serde(rename_all = "camelCase")]
    Bank {
        /// The account number.
        #[serde(serialize_with = "serialize_secret_string")]
        number: SecretString,
        /// The routing number (US) or sort code (UK).
        #[serde(serialize_with = "serialize_secret_string")]
        routing: SecretString,
        /// IBAN.
        #[serde(serialize_with = "serialize_secret_option")]
        iban: Option<SecretString>,
        /// SWIFT.
        #[serde(serialize_with = "serialize_secret_option")]
        swift: Option<SecretString>,
        /// BIC.
        #[serde(serialize_with = "serialize_secret_option")]
        bic: Option<SecretString>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// External link; intended to be used in embedded user fields.
    #[serde(rename_all = "camelCase")]
    Link {
        /// External link URL.
        #[serde(serialize_with = "serialize_secret_string")]
        url: SecretString,
        /// Optional label for the link.
        #[serde(
            default,
            serialize_with = "serialize_secret_option",
            skip_serializing_if = "Option::is_none"
        )]
        label: Option<SecretString>,
        /// Optional title for the link.
        #[serde(
            default,
            serialize_with = "serialize_secret_option",
            skip_serializing_if = "Option::is_none"
        )]
        title: Option<SecretString>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Standalone password; intended to be used in embedded user fields.
    #[serde(rename_all = "camelCase")]
    Password {
        /// Password secret.
        #[serde(serialize_with = "serialize_secret_string")]
        password: SecretString,
        /// Optional name for the password.
        ///
        /// This could be a username, account name or other label
        /// the user wants to associate with this password.
        #[serde(
            default,
            serialize_with = "serialize_secret_option",
            skip_serializing_if = "Option::is_none"
        )]
        name: Option<SecretString>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// Identity secret for passports, driving licenses etc.
    #[serde(rename_all = "camelCase")]
    Identity {
        /// The kind of this identification.
        id_kind: IdentityKind,
        /// The number for the identifier.
        #[serde(serialize_with = "serialize_secret_string")]
        number: SecretString,
        /// Issue place.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issue_place: Option<String>,
        /// Issue date.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issue_date: Option<Timestamp>,
        /// Expiration date.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expiry_date: Option<Timestamp>,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
    /// AGE encryption standard.
    #[serde(rename_all = "camelCase")]
    Age {
        /// The version of AGE.
        version: AgeVersion,
        #[serde(serialize_with = "serialize_secret_string")]
        /// Secret key for the AGE identity.
        key: SecretString,
        /// Custom user data.
        #[serde(default, skip_serializing_if = "UserData::is_default")]
        user_data: UserData,
    },
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        match self {
            Secret::Note { text, user_data } => Secret::Note {
                text: secrecy::Secret::new(text.expose_secret().to_owned()),
                user_data: user_data.clone(),
            },
            Secret::File { content, user_data } => Secret::File {
                content: content.clone(),
                user_data: user_data.clone(),
            },
            Secret::Account {
                account,
                url,
                password,
                user_data,
            } => Secret::Account {
                account: account.to_owned(),
                url: url.clone(),
                password: secrecy::Secret::new(
                    password.expose_secret().to_owned(),
                ),
                user_data: user_data.clone(),
            },
            Secret::List { items, user_data } => {
                let copy = items
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
                Secret::List {
                    items: copy,
                    user_data: user_data.clone(),
                }
            }
            Secret::Pem {
                certificates,
                user_data,
            } => Secret::Pem {
                certificates: certificates.clone(),
                user_data: user_data.clone(),
            },
            Secret::Page {
                title,
                mime,
                document,
                user_data,
            } => Secret::Page {
                title: title.to_owned(),
                mime: mime.to_owned(),
                document: secrecy::Secret::new(
                    document.expose_secret().to_owned(),
                ),
                user_data: user_data.clone(),
            },
            Secret::Signer {
                private_key,
                user_data,
            } => Secret::Signer {
                private_key: private_key.clone(),
                user_data: user_data.clone(),
            },
            Secret::Contact { vcard, user_data } => Secret::Contact {
                vcard: vcard.clone(),
                user_data: user_data.clone(),
            },
            Secret::Totp { totp, user_data } => Secret::Totp {
                totp: totp.clone(),
                user_data: user_data.clone(),
            },
            Secret::Card {
                number,
                expiry,
                cvv,
                name,
                atm_pin,
                user_data,
            } => Secret::Card {
                number: number.clone(),
                expiry: expiry.clone(),
                cvv: cvv.clone(),
                name: name.clone(),
                atm_pin: atm_pin.clone(),
                user_data: user_data.clone(),
            },
            Secret::Bank {
                number,
                routing,
                iban,
                swift,
                bic,
                user_data,
            } => Secret::Bank {
                number: number.clone(),
                routing: routing.clone(),
                iban: iban.clone(),
                swift: swift.clone(),
                bic: bic.clone(),
                user_data: user_data.clone(),
            },
            Secret::Link {
                url,
                label,
                title,
                user_data,
            } => Secret::Link {
                url: url.clone(),
                label: label.clone(),
                title: title.clone(),
                user_data: user_data.clone(),
            },
            Secret::Password {
                password,
                name,
                user_data,
            } => Secret::Password {
                password: password.clone(),
                name: name.clone(),
                user_data: user_data.clone(),
            },
            Secret::Identity {
                id_kind,
                number,
                issue_place,
                issue_date,
                expiry_date,
                user_data,
            } => Secret::Identity {
                id_kind: id_kind.clone(),
                number: SecretString::new(number.expose_secret().to_owned()),
                issue_place: issue_place.clone(),
                issue_date: issue_date.clone(),
                expiry_date: expiry_date.clone(),
                user_data: user_data.clone(),
            },
            Secret::Age {
                version,
                key,
                user_data,
            } => Secret::Age {
                version: version.clone(),
                key: secrecy::Secret::new(key.expose_secret().to_owned()),
                user_data: user_data.clone(),
            },
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secret::Note { .. } => f.debug_struct("Note").finish(),
            Secret::File { content, .. } => f
                .debug_struct("File")
                .field("name", &content.name())
                .field("mime", &content.mime())
                .finish(),
            Secret::Account { account, url, .. } => f
                .debug_struct("Account")
                .field("account", account)
                .field("url", url)
                .finish(),
            Secret::List { items, .. } => {
                let keys = items.keys().collect::<Vec<_>>();
                f.debug_struct("List").field("keys", &keys).finish()
            }
            Secret::Pem { certificates, .. } => f
                .debug_struct("Pem")
                .field("size", &certificates.len())
                .finish(),
            Secret::Page { title, mime, .. } => f
                .debug_struct("Page")
                .field("title", title)
                .field("mime", mime)
                .finish(),
            Secret::Identity { .. } => f.debug_struct("Identity").finish(),
            Secret::Signer { .. } => f.debug_struct("Signer").finish(),
            Secret::Contact { .. } => f.debug_struct("Contact").finish(),
            Secret::Totp { .. } => f.debug_struct("TOTP").finish(),
            Secret::Card { .. } => f.debug_struct("Card").finish(),
            Secret::Bank { .. } => f.debug_struct("Bank").finish(),
            Secret::Link { .. } => f.debug_struct("Link").finish(),
            Secret::Password { .. } => f.debug_struct("Password").finish(),
            Secret::Age { .. } => f.debug_struct("AGE").finish(),
        }
    }
}

impl Secret {
    /// Parse key value pairs into a map.
    pub fn parse_list<S: AsRef<str>>(
        list: S,
    ) -> Result<HashMap<String, SecretString>> {
        let mut credentials = HashMap::new();
        for line in list.as_ref().lines() {
            let key_value = line.split_once('=');
            if let Some((key, value)) = key_value {
                credentials.insert(
                    key.to_string(),
                    SecretString::new(value.to_string()),
                );
            } else {
                return Err(Error::InvalidKeyValue(line.to_string()));
            }
        }
        Ok(credentials)
    }

    /// Ensure all the bytes are ASCII digits.
    pub fn ensure_ascii_digits<B: AsRef<[u8]>>(bytes: B) -> Result<()> {
        for byte in bytes.as_ref() {
            if !byte.is_ascii_digit() {
                return Err(Error::NotDigit);
            }
        }
        Ok(())
    }

    /// Get the type of this secret.
    pub fn kind(&self) -> SecretType {
        match self {
            Secret::Note { .. } => SecretType::Note,
            Secret::File { .. } => SecretType::File,
            Secret::Account { .. } => SecretType::Account,
            Secret::List { .. } => SecretType::List,
            Secret::Pem { .. } => SecretType::Pem,
            Secret::Page { .. } => SecretType::Page,
            Secret::Identity { .. } => SecretType::Identity,
            Secret::Signer { .. } => SecretType::Signer,
            Secret::Contact { .. } => SecretType::Contact,
            Secret::Totp { .. } => SecretType::Totp,
            Secret::Card { .. } => SecretType::Card,
            Secret::Bank { .. } => SecretType::Bank,
            Secret::Link { .. } => SecretType::Link,
            Secret::Password { .. } => SecretType::Password,
            Secret::Age { .. } => SecretType::Age,
        }
    }

    /// Get the user data for this secret.
    pub fn user_data(&self) -> &UserData {
        match self {
            Secret::Note { user_data, .. } => user_data,
            Secret::File { user_data, .. } => user_data,
            Secret::Account { user_data, .. } => user_data,
            Secret::List { user_data, .. } => user_data,
            Secret::Pem { user_data, .. } => user_data,
            Secret::Page { user_data, .. } => user_data,
            Secret::Identity { user_data, .. } => user_data,
            Secret::Signer { user_data, .. } => user_data,
            Secret::Contact { user_data, .. } => user_data,
            Secret::Totp { user_data, .. } => user_data,
            Secret::Card { user_data, .. } => user_data,
            Secret::Bank { user_data, .. } => user_data,
            Secret::Link { user_data, .. } => user_data,
            Secret::Password { user_data, .. } => user_data,
            Secret::Age { user_data, .. } => user_data,
        }
    }

    /// Get the mutable user data for this secret.
    pub fn user_data_mut(&mut self) -> &mut UserData {
        match self {
            Secret::Note { user_data, .. } => user_data,
            Secret::File { user_data, .. } => user_data,
            Secret::Account { user_data, .. } => user_data,
            Secret::List { user_data, .. } => user_data,
            Secret::Pem { user_data, .. } => user_data,
            Secret::Page { user_data, .. } => user_data,
            Secret::Identity { user_data, .. } => user_data,
            Secret::Signer { user_data, .. } => user_data,
            Secret::Contact { user_data, .. } => user_data,
            Secret::Totp { user_data, .. } => user_data,
            Secret::Card { user_data, .. } => user_data,
            Secret::Bank { user_data, .. } => user_data,
            Secret::Link { user_data, .. } => user_data,
            Secret::Password { user_data, .. } => user_data,
            Secret::Age { user_data, .. } => user_data,
        }
    }

    /// Attach a secret to this secret's user data.
    pub fn attach(&mut self, attachment: SecretRow) {
        self.user_data_mut().fields_mut().push(attachment);
    }

    /// Remove a secret from this secret's user data.
    pub fn detach(&mut self, id: &SecretId) {
        self.user_data_mut()
            .fields_mut()
            .retain(|row| row.id() != id);
    }

    /// Find an attachment by reference.
    pub fn find_attachment(&self, target: &SecretRef) -> Option<&SecretRow> {
        match target {
            SecretRef::Id(id) => self.find_attachment_by_id(id),
            SecretRef::Name(name) => self.find_attachment_by_name(name),
        }
    }

    /// Find an attachment by identifier.
    pub fn find_attachment_by_id(&self, id: &SecretId) -> Option<&SecretRow> {
        self.user_data().fields().iter().find(|row| row.id() == id)
    }

    /// Find an attachment by name.
    pub fn find_attachment_by_name(&self, label: &str) -> Option<&SecretRow> {
        self.user_data()
            .fields()
            .iter()
            .find(|row| row.meta().label() == label)
    }

    /// Update an attached secret.
    pub fn update_attachment(&mut self, attachment: SecretRow) -> Result<()> {
        let existing = self
            .user_data_mut()
            .fields_mut()
            .iter_mut()
            .find(|row| row.id() == attachment.id());

        if let Some(existing) = existing {
            *existing = attachment;
            Ok(())
        } else {
            Err(Error::AttachmentNotFound(*attachment.id()))
        }
    }

    /// Insert an attached secret at an index.
    ///
    /// # Panics
    ///
    /// Panics if `index > len`.
    pub fn insert_attachment(&mut self, index: usize, attachment: SecretRow) {
        self.user_data_mut().fields_mut().insert(index, attachment);
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Note {
                    text: text_a,
                    user_data: user_data_a,
                },
                Self::Note {
                    text: text_b,
                    user_data: user_data_b,
                },
            ) => {
                text_a.expose_secret() == text_b.expose_secret()
                    && user_data_a == user_data_b
            }
            (
                Self::Account {
                    account: account_a,
                    url: url_a,
                    password: password_a,
                    user_data: user_data_a,
                },
                Self::Account {
                    account: account_b,
                    url: url_b,
                    password: password_b,
                    user_data: user_data_b,
                },
            ) => {
                account_a == account_b
                    && url_a == url_b
                    && password_a.expose_secret()
                        == password_b.expose_secret()
                    && user_data_a == user_data_b
            }
            (
                Self::File {
                    content: content_a,
                    user_data: user_data_a,
                },
                Self::File {
                    content: content_b,
                    user_data: user_data_b,
                },
            ) => content_a == content_b && user_data_a == user_data_b,
            (
                Self::List {
                    items: items_a,
                    user_data: user_data_a,
                },
                Self::List {
                    items: items_b,
                    user_data: user_data_b,
                },
            ) => {
                items_a.iter().zip(items_b.iter()).all(|(a, b)| {
                    a.0 == b.0 && a.1.expose_secret() == b.1.expose_secret()
                }) && user_data_a == user_data_b
            }
            (
                Self::Pem {
                    certificates: certificates_a,
                    user_data: user_data_a,
                },
                Self::Pem {
                    certificates: certificates_b,
                    user_data: user_data_b,
                },
            ) => {
                certificates_a
                    .iter()
                    .zip(certificates_b.iter())
                    .all(|(a, b)| a.tag == b.tag && a.contents == b.contents)
                    && user_data_a == user_data_b
            }
            (
                Self::Page {
                    title: title_a,
                    mime: mime_a,
                    document: document_a,
                    user_data: user_data_a,
                },
                Self::Page {
                    title: title_b,
                    mime: mime_b,
                    document: document_b,
                    user_data: user_data_b,
                },
            ) => {
                title_a == title_b
                    && mime_a == mime_b
                    && document_a.expose_secret()
                        == document_b.expose_secret()
                    && user_data_a == user_data_b
            }
            (
                Self::Identity {
                    id_kind: id_kind_a,
                    number: number_a,
                    issue_place: issue_place_a,
                    issue_date: issue_date_a,
                    expiry_date: expiry_date_a,
                    user_data: user_data_a,
                },
                Self::Identity {
                    id_kind: id_kind_b,
                    number: number_b,
                    issue_place: issue_place_b,
                    issue_date: issue_date_b,
                    expiry_date: expiry_date_b,
                    user_data: user_data_b,
                },
            ) => {
                id_kind_a == id_kind_b
                    && number_a.expose_secret() == number_b.expose_secret()
                    && issue_place_a == issue_place_b
                    && issue_date_a == issue_date_b
                    && expiry_date_a == expiry_date_b
                    && user_data_a == user_data_b
            }

            (
                Self::Signer {
                    private_key: private_key_a,
                    user_data: user_data_a,
                },
                Self::Signer {
                    private_key: private_key_b,
                    user_data: user_data_b,
                },
            ) => private_key_a == private_key_b && user_data_a == user_data_b,
            (
                Self::Contact {
                    vcard: vcard_a,
                    user_data: user_data_a,
                },
                Self::Contact {
                    vcard: vcard_b,
                    user_data: user_data_b,
                },
            ) => vcard_a == vcard_b && user_data_a == user_data_b,
            (
                Self::Totp {
                    totp: totp_a,
                    user_data: user_data_a,
                },
                Self::Totp {
                    totp: totp_b,
                    user_data: user_data_b,
                },
            ) => totp_a == totp_b && user_data_a == user_data_b,
            (
                Self::Card {
                    number: number_a,
                    expiry: expiry_a,
                    cvv: cvv_a,
                    name: name_a,
                    atm_pin: atm_pin_a,
                    user_data: user_data_a,
                },
                Self::Card {
                    number: number_b,
                    expiry: expiry_b,
                    cvv: cvv_b,
                    name: name_b,
                    atm_pin: atm_pin_b,
                    user_data: user_data_b,
                },
            ) => {
                number_a.expose_secret() == number_b.expose_secret()
                    && expiry_a == expiry_b
                    && cvv_a.expose_secret() == cvv_b.expose_secret()
                    && name_a.as_ref().map(|s| s.expose_secret())
                        == name_b.as_ref().map(|s| s.expose_secret())
                    && atm_pin_a.as_ref().map(|s| s.expose_secret())
                        == atm_pin_b.as_ref().map(|s| s.expose_secret())
                    && user_data_a == user_data_b
            }

            (
                Self::Bank {
                    number: number_a,
                    routing: routing_a,
                    iban: iban_a,
                    swift: swift_a,
                    bic: bic_a,
                    user_data: user_data_a,
                },
                Self::Bank {
                    number: number_b,
                    routing: routing_b,
                    iban: iban_b,
                    swift: swift_b,
                    bic: bic_b,
                    user_data: user_data_b,
                },
            ) => {
                number_a.expose_secret() == number_b.expose_secret()
                    && routing_a.expose_secret() == routing_b.expose_secret()
                    && iban_a.as_ref().map(|s| s.expose_secret())
                        == iban_b.as_ref().map(|s| s.expose_secret())
                    && swift_a.as_ref().map(|s| s.expose_secret())
                        == swift_b.as_ref().map(|s| s.expose_secret())
                    && bic_a.as_ref().map(|s| s.expose_secret())
                        == bic_b.as_ref().map(|s| s.expose_secret())
                    && user_data_a == user_data_b
            }

            (
                Self::Link {
                    url: url_a,
                    label: label_a,
                    title: title_a,
                    user_data: user_data_a,
                },
                Self::Link {
                    url: url_b,
                    label: label_b,
                    title: title_b,
                    user_data: user_data_b,
                },
            ) => {
                url_a.expose_secret() == url_b.expose_secret()
                    && label_a.as_ref().map(|s| s.expose_secret())
                        == label_b.as_ref().map(|s| s.expose_secret())
                    && title_a.as_ref().map(|s| s.expose_secret())
                        == title_b.as_ref().map(|s| s.expose_secret())
                    && user_data_a == user_data_b
            }

            (
                Self::Password {
                    password: password_a,
                    name: name_a,
                    user_data: user_data_a,
                },
                Self::Password {
                    password: password_b,
                    name: name_b,
                    user_data: user_data_b,
                },
            ) => {
                password_a.expose_secret() == password_b.expose_secret()
                    && name_a.as_ref().map(|s| s.expose_secret())
                        == name_b.as_ref().map(|s| s.expose_secret())
                    && user_data_a == user_data_b
            }

            (
                Self::Age {
                    version: version_a,
                    key: key_a,
                    user_data: user_data_a,
                },
                Self::Age {
                    version: version_b,
                    key: key_b,
                    user_data: user_data_b,
                },
            ) => {
                version_a == version_b
                    && key_a.expose_secret() == key_b.expose_secret()
                    && user_data_a == user_data_b
            }

            _ => false,
        }
    }
}
impl Eq for Secret {}

impl Default for Secret {
    fn default() -> Self {
        Self::Note {
            text: secrecy::Secret::new(String::new()),
            user_data: Default::default(),
        }
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
    /// Identity numbers.
    pub const IDENTIFICATION: u8 = 7;
    /// Private signing key.
    pub const SIGNER: u8 = 8;
    /// Contact vCard.
    pub const CONTACT: u8 = 9;
    /// Time-based one time passcode.
    pub const TOTP: u8 = 10;
    /// Credit or debit card.
    pub const CARD: u8 = 11;
    /// Bank account.
    pub const BANK: u8 = 12;
    /// External link.
    pub const LINK: u8 = 13;
    /// Standalone password.
    pub const PASSWORD: u8 = 14;
    /// [AGE](https://age-encryption.org/v1) identity.
    pub const AGE: u8 = 15;
}

impl Encode for Secret {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
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
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
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

impl TryFrom<PathBuf> for Secret {
    type Error = Error;
    fn try_from(path: PathBuf) -> Result<Self> {
        Ok(Secret::File {
            content: FileContent::External {
                name: basename(&path),
                size: 0,
                checksum: [0; 32],
                mime: guess_mime(&path)?,
                path: Some(path),
            },
            user_data: Default::default(),
        })
    }
}

impl From<SecretString> for Secret {
    fn from(password: SecretString) -> Self {
        Secret::Password {
            password,
            name: None,
            user_data: Default::default(),
        }
    }
}

impl From<Url> for Secret {
    fn from(url: Url) -> Self {
        Secret::Link {
            url: SecretString::new(url.to_string()),
            label: None,
            title: None,
            user_data: Default::default(),
        }
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Self {
        Secret::Note {
            text: SecretString::new(text),
            user_data: Default::default(),
        }
    }
}

impl From<HashMap<String, SecretString>> for Secret {
    fn from(items: HashMap<String, SecretString>) -> Self {
        Secret::List {
            items,
            user_data: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        decode, encode,
        signer::{ecdsa::SingleParty, Signer},
        test_utils::*,
    };
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    #[test]
    fn secret_serde() -> Result<()> {
        let secret = Secret::Note {
            text: secrecy::Secret::new(String::from("foo")),
            user_data: Default::default(),
        };
        let value = serde_json::to_string_pretty(&secret)?;
        let result: Secret = serde_json::from_str(&value)?;
        assert_eq!(secret, result);
        Ok(())
    }

    #[test]
    fn secret_encode_user_data() -> Result<()> {
        let mut user_data: UserData = Default::default();
        user_data.set_comment(Some("Comment".to_string()));
        user_data.set_recovery_note(Some("Recovery".to_string()));

        let card = Secret::Card {
            number: SecretString::new("1234567890123456".to_string()),
            expiry: Default::default(),
            cvv: SecretString::new("123".to_string()),
            name: Some(SecretString::new("Miss Jane Doe".to_string())),
            atm_pin: None,
            user_data: Default::default(),
        };
        let card_meta =
            SecretMeta::new("Embedded card".to_string(), card.kind());

        let bank = Secret::Bank {
            number: SecretString::new("12345678".to_string()),
            routing: SecretString::new("00-00-00".to_string()),
            iban: None,
            swift: None,
            bic: None,
            user_data: Default::default(),
        };
        let bank_meta =
            SecretMeta::new("Embedded bank".to_string(), bank.kind());

        user_data.push(SecretRow::new(SecretId::new_v4(), card_meta, card));
        user_data.push(SecretRow::new(SecretId::new_v4(), bank_meta, bank));

        let text = r#"BEGIN:VCARD
VERSION:4.0
FN:Mock Bank
END:VCARD"#;

        let vcard: Vcard = text.try_into()?;
        let secret = Secret::Contact {
            vcard: Box::new(vcard),
            user_data,
        };

        let encoded = encode(&secret)?;
        let decoded: Secret = decode(&encoded)?;

        assert_eq!(secret, decoded);
        assert_eq!(2, decoded.user_data().len());

        assert!(matches!(decoded.user_data().comment(), Some("Comment")));
        assert!(matches!(
            decoded.user_data().recovery_note(),
            Some("Recovery")
        ));

        Ok(())
    }

    #[test]
    fn secret_encode_note() -> Result<()> {
        let user_data: UserData = Default::default();
        let secret = Secret::Note {
            text: secrecy::Secret::new(String::from("My Note")),
            user_data,
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_file() -> Result<()> {
        let (_, secret, _, _) = mock_secret_file(
            "Mock file",
            "hello.txt",
            "text/plain",
            "hello".as_bytes().to_vec(),
        )?;
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
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);

        let secret_no_url = Secret::Account {
            account: "Email".to_string(),
            url: None,
            password: secrecy::Secret::new("mock-password".to_string()),
            user_data: Default::default(),
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
        let secret = Secret::List {
            items: credentials,
            user_data: Default::default(),
        };

        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        // To assert consistently we must sort and to sort
        // we need to expose the underlying secret string
        // so we get an Ord implementation
        let (secret_a, secret_b) = if let (
            Secret::List { items: a, .. },
            Secret::List { items: b, .. },
        ) = (secret, decoded)
        {
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

        let certificates = pem::parse_many(certificate).unwrap();
        let secret = Secret::Pem {
            certificates,
            user_data: Default::default(),
        };
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
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_signer() -> Result<()> {
        let signer = SingleParty::new_random();
        let private_key =
            SecretSigner::SinglePartyEcdsa(SecretVec::new(signer.to_bytes()));
        let secret = Secret::Signer {
            private_key,
            user_data: Default::default(),
        };
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
        let secret = Secret::Contact {
            vcard: Box::new(vcard),
            user_data: Default::default(),
        };
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

        let secret = Secret::Totp {
            totp,
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_card() -> Result<()> {
        let secret = Secret::Card {
            number: SecretString::new("1234567890123456".to_string()),
            expiry: Default::default(),
            cvv: SecretString::new("123".to_string()),
            name: Some(SecretString::new("Mock name".to_string())),
            atm_pin: Some(SecretString::new("123456".to_string())),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_bank() -> Result<()> {
        let secret = Secret::Bank {
            number: SecretString::new("12345678".to_string()),
            routing: SecretString::new("01-02-03".to_string()),
            iban: Some(SecretString::new("GB 23 01020312345678".to_string())),
            swift: Some(SecretString::new("XCVDFGB".to_string())),
            bic: Some(SecretString::new("6789".to_string())),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_link() -> Result<()> {
        let secret = Secret::Link {
            url: SecretString::new("https://example.com".to_string()),
            label: Some(SecretString::new("Example".to_string())),
            title: Some(SecretString::new(
                "Open example website".to_string(),
            )),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_password() -> Result<()> {
        let secret = Secret::Password {
            password: SecretString::new("abracadabra".to_string()),
            name: Some(SecretString::new("Open the magic cave".to_string())),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;

        assert_eq!(secret, decoded);
        Ok(())
    }

    #[test]
    fn secret_encode_identification() -> Result<()> {
        let secret = Secret::Identity {
            id_kind: IdentityKind::IdCard,
            number: SecretString::new("12345678".to_string()),
            issue_place: Some("Mock city".to_string()),
            issue_date: Some(Default::default()),
            expiry_date: Some(Default::default()),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);

        Ok(())
    }

    #[test]
    fn secret_encode_age() -> Result<()> {
        let secret = Secret::Age {
            version: Default::default(),
            key: age::x25519::Identity::generate().to_string(),
            user_data: Default::default(),
        };
        let encoded = encode(&secret)?;
        let decoded = decode(&encoded)?;
        assert_eq!(secret, decoded);

        Ok(())
    }
}
