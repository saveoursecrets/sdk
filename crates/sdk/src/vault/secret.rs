//! Types used to represent vault meta data and secrets.

use bitflags::bitflags;
use ed25519_dalek::SECRET_KEY_LENGTH;
use pem::Pem;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{
    de::{self, Deserializer, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Serialize, Serializer,
};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
};
use totp_rs::TOTP;
use url::Url;
use urn::Urn;
use uuid::Uuid;
use vcard4::{self, Vcard};
use zxcvbn::Entropy;

use crate::{
    passwd::generator::measure_entropy,
    signer::{
        ecdsa::{self, BoxedEcdsaSigner},
        ed25519::{self, BoxedEd25519Signer},
    },
    vault::VaultId,
    Error, Result, UtcDateTime,
};

use std::path::PathBuf;

/// Path to a secret.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPath(pub VaultId, pub SecretId);

impl SecretPath {
    /// Folder identifier.
    pub fn folder_id(&self) -> &VaultId {
        &self.0
    }

    /// Secret identifier.
    pub fn secret_id(&self) -> &SecretId {
        &self.1
    }
}

bitflags! {
    /// Bit flags for a secret.
    #[derive(Default, Serialize, Deserialize, Debug, Clone)]
    #[serde(transparent)]
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
    secret: &SecretBox<Vec<u8>>,
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

fn is_empty_secret_vec(value: &SecretBox<Vec<u8>>) -> bool {
    value.expose_secret().is_empty()
}

fn default_secret_vec() -> SecretBox<Vec<u8>> {
    SecretBox::new(Box::new(Vec::new()))
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
#[typeshare::typeshare]
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
#[typeshare::typeshare]
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    /// Kind of the secret.
    pub(crate) kind: SecretType,
    /// Flags for the secret.
    pub(crate) flags: SecretFlags,
    /// Human-friendly label for the secret.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
    /// Collection of tags.
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub(crate) tags: HashSet<String>,
    /// Whether this secret is a favorite.
    pub(crate) favorite: bool,
    /// A URN identifier for this secret.
    ///
    /// This is used when an identity vault stores passphrases
    /// for other vault folders on behalf of a user and can also
    /// be used to assign a predictable identifier for a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) urn: Option<Urn>,
    /// An optional owner identifier.
    ///
    /// This can be used when creating secrets on behalf of a
    /// third-party plugin or application to indicate the identifier
    /// of the third-party application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner_id: Option<String>,
    /// Date created timestamp.
    pub(crate) date_created: UtcDateTime,
    /// Last updated timestamp.
    #[serde(skip_deserializing)]
    pub(crate) last_updated: UtcDateTime,
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

    /// Label for the secret.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the label for the secret.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }

    /// Kind of the secret.
    pub fn kind(&self) -> &SecretType {
        &self.kind
    }

    /// Created date and time.
    pub fn date_created(&self) -> &UtcDateTime {
        &self.date_created
    }

    /// Set the created date and time.
    pub fn set_date_created(&mut self, date_created: UtcDateTime) {
        self.date_created = date_created;
    }

    /// Update the last updated timestamp to now.
    pub fn touch(&mut self) {
        self.last_updated = Default::default();
    }

    /// Last updated date and time.
    pub fn last_updated(&self) -> &UtcDateTime {
        &self.last_updated
    }

    /// Set the updated date and time.
    pub fn set_last_updated(&mut self, last_updated: UtcDateTime) {
        self.last_updated = last_updated;
    }

    /// Secret tags.
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

/// Secret type that encapsulates a signing private key.
#[derive(Serialize, Deserialize)]
pub enum SecretSigner {
    /// Single party Ethereum-compatible ECDSA signing private key.
    #[serde(serialize_with = "serialize_secret_buffer")]
    SinglePartyEcdsa(SecretBox<Vec<u8>>),
    /// Single party Ed25519 signing private key.
    #[serde(serialize_with = "serialize_secret_buffer")]
    SinglePartyEd25519(SecretBox<Vec<u8>>),
}

impl From<ecdsa::SingleParty> for SecretSigner {
    fn from(value: ecdsa::SingleParty) -> Self {
        Self::SinglePartyEcdsa(SecretBox::new(
            value.0.to_bytes().to_vec().into(),
        ))
    }
}

impl From<ed25519::SingleParty> for SecretSigner {
    fn from(value: ed25519::SingleParty) -> Self {
        Self::SinglePartyEd25519(SecretBox::new(
            value.0.to_bytes().to_vec().into(),
        ))
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
        Self::SinglePartyEcdsa(SecretBox::new(vec![].into()))
    }
}

impl Clone for SecretSigner {
    fn clone(&self) -> Self {
        match self {
            Self::SinglePartyEcdsa(buffer) => Self::SinglePartyEcdsa(
                SecretBox::new(buffer.expose_secret().to_vec().into()),
            ),
            Self::SinglePartyEd25519(buffer) => Self::SinglePartyEd25519(
                SecretBox::new(buffer.expose_secret().to_vec().into()),
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

/// Secret with it's associated meta data and identifier.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SecretRow {
    /// Identifier for the secret.
    pub(crate) id: SecretId,
    /// Meta data for the secret.
    pub(crate) meta: SecretMeta,
    /// The data for the secret.
    pub(crate) secret: Secret,
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

impl From<SecretRow> for SecretMeta {
    fn from(value: SecretRow) -> Self {
        value.meta
    }
}

impl From<SecretRow> for Secret {
    fn from(value: SecretRow) -> Self {
        value.secret
    }
}

/// Collection of custom user data.
#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UserData {
    /// Collection of custom user_data.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) fields: Vec<SecretRow>,
    /// Comment for the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) comment: Option<String>,
    /// Recovery notes.
    ///
    /// These are notes specific for a person that might recover
    /// the vault information and is intended to provide additional
    /// information on how to use this secret in the event of an
    /// emergency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_note: Option<String>,
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
        buffer: SecretBox<Vec<u8>>,

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
            buffer: SecretBox::new(vec![].into()),
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
                buffer: SecretBox::new(
                    buffer.expose_secret().to_vec().into(),
                ),
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
        /// The account password.
        #[serde(serialize_with = "serialize_secret_string")]
        password: SecretString,
        /// Optional URLs associated with the account.
        url: Vec<Url>,
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
        expiry: Option<UtcDateTime>,
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
        issue_date: Option<UtcDateTime>,
        /// Expiration date.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expiry_date: Option<UtcDateTime>,
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
                text: SecretBox::new(text.expose_secret().to_owned().into()),
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
                password: SecretBox::new(
                    password.expose_secret().to_owned().into(),
                ),
                user_data: user_data.clone(),
            },
            Secret::List { items, user_data } => {
                let copy = items
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.to_owned(),
                            SecretBox::new(
                                v.expose_secret().to_owned().into(),
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
                document: SecretBox::new(
                    document.expose_secret().to_owned().into(),
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
                number: number.expose_secret().to_owned().into(),
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
                key: SecretBox::new(key.expose_secret().to_owned().into()),
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
    /*
    /// Redact this secret clearing all sensitive information.
    ///
    /// Can be used to send an outline of a secret without exposing
    /// any actual private information.
    pub fn redact(&mut self) {
        match self {
            Secret::Account { password, .. } => {
                *password = SecretBox::new(String::new().into());
            }
            Secret::Note { text, .. } => {
                *text = SecretBox::new(String::new().into());
            }
            Secret::File { content, .. } => {
                if let FileContent::Embedded {
                    name,
                    mime,
                    buffer,
                    checksum,
                } = content
                {
                    *buffer = SecretBox::new(Vec::with_capacity(0).into());
                }
            }
            Secret::List { items, .. } => {
                for (name, value) in items {
                    *value = SecretBox::new(String::new().into());
                }
            }
            Secret::Pem { certificates, .. } => {
                // *text = SecretBox::new(String::new().into());
                todo!();
            }
            Secret::Page { document, .. } => {
                *document = SecretBox::new(String::new().into());
            }
            Secret::Contact { vcard, .. } => {
                todo!();
            }
            Secret::Totp { totp, .. } => {
                todo!();
            }
            Secret::Card { number, .. } => {
                todo!();
            }
            Secret::Bank { number, .. } => {
                *number = SecretBox::new(String::new().into());
            }
            Secret::Link { url, .. } => {
                *url = SecretBox::new(String::new().into());
            }
            Secret::Password { password, .. } => {
                *password = SecretBox::new(String::new().into());
            }
            Secret::Identity { number, .. } => {
                *number = SecretBox::new(String::new().into());
            }
            Secret::Age { .. } => {
                todo!();
            }
            Secret::Signer { .. } => {
                todo!();
            }
        }
    }
    */

    /// Measure entropy for a password and compute a SHA-1 checksum.
    ///
    /// Only applies to account and password types, other
    /// types will yield `None.`
    pub fn check_password(
        secret: &Secret,
    ) -> Result<Option<(Option<Entropy>, Vec<u8>)>> {
        // TODO: remove Result type from function return value
        use sha1::{Digest, Sha1};
        match secret {
            Secret::Account {
                account, password, ..
            } => {
                let hash = Sha1::digest(password.expose_secret().as_bytes());

                // Zxcvbn cannot handle empty passwords but we
                // need to handle this gracefully
                if password.expose_secret().is_empty() {
                    Ok(Some((None, hash.to_vec())))
                } else {
                    let entropy =
                        measure_entropy(password.expose_secret(), &[account]);
                    Ok(Some((Some(entropy), hash.to_vec())))
                }
            }
            Secret::Password { password, name, .. } => {
                let inputs = if let Some(name) = name {
                    vec![&name.expose_secret()[..]]
                } else {
                    vec![]
                };

                let hash = Sha1::digest(password.expose_secret().as_bytes());

                // Zxcvbn cannot handle empty passwords but we
                // need to handle this gracefully
                if password.expose_secret().is_empty() {
                    Ok(Some((None, hash.to_vec())))
                } else {
                    let entropy = measure_entropy(
                        password.expose_secret(),
                        inputs.as_slice(),
                    );

                    Ok(Some((Some(entropy), hash.to_vec())))
                }
            }
            _ => Ok(None),
        }
    }

    /// Value formatted to copy to the clipboard.
    pub fn copy_value_unsafe(&self) -> Option<String> {
        match self {
            Secret::Account { password, .. } => {
                Some(password.expose_secret().to_owned())
            }
            Secret::Note { text, .. } => {
                Some(text.expose_secret().to_owned())
            }
            Secret::File { content, .. } => Some(content.name().to_string()),
            Secret::List { items, .. } => {
                let mut s = String::new();
                for (name, value) in items {
                    s.push_str(name);
                    s.push('=');
                    s.push_str(value.expose_secret());
                    s.push('\n');
                }
                Some(s)
            }
            Secret::Pem { certificates, .. } => {
                let text: Vec<String> =
                    certificates.iter().map(|s| s.to_string()).collect::<_>();
                Some(text.join("\n"))
            }
            Secret::Page { document, .. } => {
                Some(document.expose_secret().to_owned())
            }
            Secret::Contact { vcard, .. } => Some(vcard.to_string()),
            Secret::Totp { totp, .. } => Some(totp.get_url()),
            Secret::Card { number, .. } => {
                Some(number.expose_secret().to_string())
            }
            // TODO: concatenate fields
            Secret::Bank { number, .. } => {
                Some(number.expose_secret().to_string())
            }
            Secret::Link { url, .. } => Some(url.expose_secret().to_string()),
            Secret::Password { password, .. } => {
                Some(password.expose_secret().to_string())
            }
            Secret::Identity { number, .. } => {
                Some(number.expose_secret().to_string())
            }
            Secret::Age { .. } => None,
            Secret::Signer { .. } => None,
        }
    }

    /// Plain text unencrypted display for secrets
    /// that can be represented as UTF-8 text.
    ///
    /// Typically used to copy secrets to the
    /// clipboard.
    ///
    /// This method is preferred over implementing the
    /// `Display` trait to make it easier to audit where
    /// secrets may be exposed as plain text.
    ///
    /// For some secrets where it may be ambiguous which field
    /// to expose we keep it simple, for example, the `Card` variant
    /// exposes the card number. An exception is the `Bank` variant
    /// where we expose the bank number and routing number delimited
    /// by a newline.
    ///
    /// The `Signer`, `File` and `Age` secret variants are not supported.
    pub fn display_unsafe(&self) -> Option<String> {
        match self {
            Secret::Note { text, .. } => {
                Some(text.expose_secret().to_string())
            }
            Secret::Account { password, .. }
            | Secret::Password { password, .. } => {
                Some(password.expose_secret().to_string())
            }
            Secret::List { items, .. } => Some(Secret::encode_list(items)),
            Secret::Link { url, .. } => Some(url.expose_secret().to_string()),
            Secret::Pem { certificates, .. } => {
                Some(pem::encode_many(certificates))
            }
            Secret::Page { document, .. } => {
                Some(document.expose_secret().to_string())
            }
            Secret::Card { number, .. } | Secret::Identity { number, .. } => {
                Some(number.expose_secret().to_string())
            }
            Secret::Bank {
                number, routing, ..
            } => Some(format!(
                "{}\n{}",
                number.expose_secret(),
                routing.expose_secret()
            )),
            Secret::Contact { vcard, .. } => Some(vcard.to_string()),
            Secret::Totp { totp, .. } => Some(totp.get_url()),
            _ => None,
        }
    }

    /// Decode key value pairs into a map.
    pub fn decode_list<S: AsRef<str>>(
        list: S,
    ) -> Result<HashMap<String, SecretString>> {
        let mut credentials = HashMap::new();
        for line in list.as_ref().lines() {
            let key_value = line.split_once('=');
            if let Some((key, value)) = key_value {
                credentials.insert(key.to_string(), value.to_string().into());
            } else {
                return Err(Error::InvalidKeyValue(line.to_string()));
            }
        }
        Ok(credentials)
    }

    /// Collection of website URLs associated with
    /// this secret.
    ///
    /// Used by the search index to locate secrets by
    /// associated URL.
    pub fn websites(&self) -> Option<Vec<&Url>> {
        match self {
            Self::Account { url, .. } => Some(url.iter().collect()),
            _ => None,
        }
    }

    /// Encode a map into key value pairs.
    pub fn encode_list(list: &HashMap<String, SecretString>) -> String {
        let mut output = String::new();
        for (k, v) in list {
            output.push_str(&format!("{}={}", k, v.expose_secret()));
            output.push('\n');
        }
        output
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

    /// Attach a custom field to this secret's user data.
    pub fn add_field(&mut self, field: SecretRow) {
        self.user_data_mut().fields_mut().push(field);
    }

    /// Remove a custom field from this secret's user data.
    pub fn remove_field(&mut self, id: &SecretId) {
        self.user_data_mut()
            .fields_mut()
            .retain(|row| row.id() != id);
    }

    /// Insert a custom field at an index.
    ///
    /// # Panics
    ///
    /// Panics if `index > len`.
    pub fn insert_field(&mut self, index: usize, field: SecretRow) {
        self.user_data_mut().fields_mut().insert(index, field);
    }

    /// Find a custom field by reference.
    pub fn find_field_by_ref(
        &self,
        target: &SecretRef,
    ) -> Option<&SecretRow> {
        match target {
            SecretRef::Id(id) => self.find_field_by_id(id),
            SecretRef::Name(name) => self.find_field_by_name(name),
        }
    }

    /// Find a custom field by identifier.
    pub fn find_field_by_id(&self, id: &SecretId) -> Option<&SecretRow> {
        self.user_data().fields().iter().find(|row| row.id() == id)
    }

    /// Find a custom field by name.
    pub fn find_field_by_name(&self, label: &str) -> Option<&SecretRow> {
        self.user_data()
            .fields()
            .iter()
            .find(|row| row.meta().label() == label)
    }

    /// Update a custom field secret.
    pub fn update_field(&mut self, field: SecretRow) -> Result<()> {
        let existing = self
            .user_data_mut()
            .fields_mut()
            .iter_mut()
            .find(|row| row.id() == field.id());

        if let Some(existing) = existing {
            *existing = field;
            Ok(())
        } else {
            Err(Error::FieldNotFound(*field.id()))
        }
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
                certificates_a.iter().zip(certificates_b.iter()).all(
                    |(a, b)| {
                        a.tag() == b.tag() && a.contents() == b.contents()
                    },
                ) && user_data_a == user_data_b
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
            text: SecretBox::new(String::new().into()),
            user_data: Default::default(),
        }
    }
}

/// Type identifiers for the secret enum variants.
///
/// Used internally for encoding / decoding.
mod kind {
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

impl TryFrom<PathBuf> for Secret {
    type Error = Error;
    fn try_from(path: PathBuf) -> Result<Self> {
        Ok(Secret::File {
            content: FileContent::External {
                name: crate::storage::basename(&path),
                size: 0,
                checksum: [0; 32],
                mime: crate::storage::guess_mime(&path)?,
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
            url: url.to_string().into(),
            label: None,
            title: None,
            user_data: Default::default(),
        }
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Self {
        Secret::Note {
            text: text.into(),
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
