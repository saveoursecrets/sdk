use rs_merkle::{algorithms::Sha256, Hasher};
use serde::{Deserialize, Serialize};

use binary_stream::{BinaryReader, Decode, Endian};

use bitflags::bitflags;
use secrecy::{ExposeSecret, SecretString};
use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::HashMap,
    fmt,
    fs::File,
    io::{Cursor, Read, Seek, Write},
    path::Path,
    str::FromStr,
};
use urn::Urn;
use uuid::Uuid;

use crate::{
    commit::CommitHash,
    constants::{DEFAULT_VAULT_NAME, VAULT_IDENTITY},
    crypto::{
        aesgcm256,
        secret_key::{SecretKey, Seed},
        xchacha20poly1305, AeadPack, Algorithm, Nonce,
    },
    decode, encode,
    encoding::v1::VERSION,
    events::{ReadEvent, WriteEvent},
    formats::FileIdentity,
    passwd::diceware::generate_passphrase,
    vault::secret::SecretId,
    Error, Result, Timestamp,
};

/// Identifier for vaults.
pub type VaultId = Uuid;

bitflags! {
    /// Bit flags for a vault.
    #[derive(Default, Serialize, Deserialize)]
    pub struct VaultFlags: u64 {
        /// Indicates this vault should be treated as the default folder.
        const DEFAULT           =        0b0000000000000001;
        /// Indicates this vault is an identity vault used to authenticate
        /// a user.
        const IDENTITY          =        0b0000000000000010;
        /// Indicates this vault is to be used as an archive.
        const ARCHIVE           =        0b0000000000000100;
        /// Indicates this vault is to be used for two-factor authentication.
        const AUTHENTICATOR     =        0b0000000000001000;
        /// Indicates this vault is to be used to store contacts.
        const CONTACT           =        0b0000000000010000;
        /// Indicates this vault is a system vault and should
        /// not be presented to the account holder when listing
        /// available vaults.
        const SYSTEM            =        0b0000000000100000;
        /// Indicates this vault is to be used to store device
        /// specific information such as key shares or device
        /// specific private keys.
        ///
        /// Typically these vaults should also be assigned the
        /// NO_SYNC_SELF flag.
        const DEVICE            =        0b0000000001000000;
        /// Indicates this vault should not be synced with
        /// devices owned by the account holder.
        ///
        /// You may want to combine this with NO_SYNC_OTHER
        /// to completely ignore this vault from sync operations.
        ///
        /// This is useful for storing device specific keys.
        const NO_SYNC_SELF      =        0b0000000010000000;
        /// Idnicates this vault should not be synced with
        /// devices owned by other accounts.
        const NO_SYNC_OTHER     =        0b0000000100000000;
    }
}

impl VaultFlags {
    /// Determine if this vault is a default vault.
    pub fn is_default(&self) -> bool {
        self.contains(VaultFlags::DEFAULT)
    }

    /// Determine if this vault is an identity vault.
    pub fn is_identity(&self) -> bool {
        self.contains(VaultFlags::IDENTITY)
    }

    /// Determine if this vault is an archive vault.
    pub fn is_archive(&self) -> bool {
        self.contains(VaultFlags::ARCHIVE)
    }

    /// Determine if this vault is an authenticator vault.
    pub fn is_authenticator(&self) -> bool {
        self.contains(VaultFlags::AUTHENTICATOR)
    }

    /// Determine if this vault is for contacts.
    pub fn is_contact(&self) -> bool {
        self.contains(VaultFlags::CONTACT)
    }

    /// Determine if this vault is for system specific information.
    pub fn is_system(&self) -> bool {
        self.contains(VaultFlags::SYSTEM)
    }

    /// Determine if this vault is for device specific information.
    pub fn is_device(&self) -> bool {
        self.contains(VaultFlags::DEVICE)
    }

    /// Determine if this vault is set to ignore sync
    /// with other devices owned by the account holder.
    pub fn is_no_sync_self(&self) -> bool {
        self.contains(VaultFlags::NO_SYNC_SELF)
    }

    /// Determine if this vault is set to ignore sync
    /// with devices owned by other accounts.
    pub fn is_no_sync_other(&self) -> bool {
        self.contains(VaultFlags::NO_SYNC_OTHER)
    }
}

/// Vault meta data.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    /// Date created timestamp.
    pub(crate) date_created: Timestamp,
    /// Private human-friendly description of the vault.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
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

    /// Date this vault was initialized.
    pub fn date_created(&self) -> &Timestamp {
        &self.date_created
    }
}

/// Reference to a vault using an id or a named label.
#[derive(Debug, Clone)]
pub enum VaultRef {
    /// Vault identifier.
    Id(VaultId),
    /// Vault label.
    Name(String),
}

impl fmt::Display for VaultRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for VaultRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(id) = Uuid::parse_str(s) {
            Ok(Self::Id(id))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

/// Type to represent a secret as an encrypted pair of meta data
/// and secret data.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry(pub AeadPack, pub AeadPack);

/// Type to represent an encrypted secret with an associated commit hash.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultCommit(pub CommitHash, pub VaultEntry);

/// Trait that defines the operations on an encrypted vault.
///
/// The storage may be in-memory, backed by a file on disc or another
/// destination for the encrypted bytes.
///
/// Use `Cow` smart pointers because when we are reading
/// from an in-memory `Vault` we can return references whereas
/// other containers such as file access would return owned data.
pub trait VaultAccess {
    /// Get the vault summary.
    fn summary(&self) -> Result<Summary>;

    /// Get the name of a vault.
    fn vault_name(&self) -> Result<Cow<'_, str>>;

    /// Set the name of a vault.
    fn set_vault_name(&mut self, name: String) -> Result<WriteEvent<'_>>;

    /// Set the vault meta data.
    fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<WriteEvent<'_>>;

    /// Add an encrypted secret to the vault.
    fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>>;

    /// Insert an encrypted secret to the vault with the given id.
    ///
    /// Used internally to support consistent identifiers when
    /// mirroring in the `Gatekeeper` implementation.
    #[doc(hidden)]
    fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>>;

    /// Get an encrypted secret from the vault.
    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)>;

    /// Update an encrypted secret in the vault.
    fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent<'_>>>;

    /// Remove an encrypted secret from the vault.
    fn delete(&mut self, id: &SecretId) -> Result<Option<WriteEvent<'_>>>;
}

/// Authentication information.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Auth {
    /// Salt used to derive a secret key from the passphrase.
    pub(crate) salt: Option<String>,
    /// Additional entropy to concatenate with the vault passphrase
    /// before deriving the secret key.
    pub(crate) seed: Option<Seed>,
}

/// Summary holding basic file information such as version,
/// unique identifier and name.
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub struct Summary {
    /// Encoding version.
    pub(crate) version: u16,
    /// Unique identifier for the vault.
    pub(crate) id: VaultId,
    /// Vault name.
    pub(crate) name: String,
    /// Encryption algorithm.
    #[serde(skip)]
    pub(crate) algorithm: Algorithm,
    /// Flags for the vault.
    pub(crate) flags: VaultFlags,
}

impl Ord for Summary {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Summary {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Version {} using {}\n{} {}",
            self.version, self.algorithm, self.name, self.id
        )
    }
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            version: VERSION,
            algorithm: Default::default(),
            id: Uuid::new_v4(),
            name: DEFAULT_VAULT_NAME.to_string(),
            flags: Default::default(),
        }
    }
}

impl Summary {
    /// Create a new summary.
    pub fn new(
        id: VaultId,
        name: String,
        algorithm: Algorithm,
        flags: VaultFlags,
    ) -> Self {
        Self {
            version: VERSION,
            algorithm,
            id,
            name,
            flags,
        }
    }

    /// Get the version identifier.
    pub fn version(&self) -> &u16 {
        &self.version
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Get the unique identifier.
    pub fn id(&self) -> &VaultId {
        &self.id
    }

    /// Get the public name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the public name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Get the vault flags.
    pub fn flags(&self) -> &VaultFlags {
        &self.flags
    }

    /// Get a mutable reference to the vault flags.
    pub fn flags_mut(&mut self) -> &mut VaultFlags {
        &mut self.flags
    }
}

/// File header, identifier and version information
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Header {
    pub(crate) summary: Summary,
    pub(crate) meta: Option<AeadPack>,
    pub(crate) auth: Auth,
}

impl Header {
    /// Create a new header.
    pub fn new(
        id: VaultId,
        name: String,
        algorithm: Algorithm,
        flags: VaultFlags,
    ) -> Self {
        Self {
            summary: Summary::new(id, name, algorithm, flags),
            meta: None,
            auth: Default::default(),
        }
    }

    /// Get the vault identifier.
    pub fn id(&self) -> &VaultId {
        self.summary.id()
    }

    /// Clear an existing salt.
    ///
    /// Required when changing passwords so we can initialize
    /// a vault that is already initialized.
    pub(crate) fn clear_salt(&mut self) {
        self.auth.salt = None;
    }

    /// Get the public name for this vault.
    pub fn name(&self) -> &str {
        &self.summary.name
    }

    /// Set the public name for this vault.
    pub fn set_name(&mut self, name: String) {
        self.summary.set_name(name);
    }

    /// Get the encrypted meta data for the vault.
    pub fn meta(&self) -> Option<&AeadPack> {
        self.meta.as_ref()
    }

    /// Set the encrypted meta data for the vault.
    pub fn set_meta(&mut self, meta: Option<AeadPack>) {
        self.meta = meta;
    }

    /// Read the content offset for a vault file verifying
    /// the identity bytes first.
    pub fn read_content_offset<P: AsRef<Path>>(path: P) -> Result<u64> {
        let mut stream = File::open(path.as_ref())?;
        Header::read_content_offset_stream(&mut stream)
    }

    /// Read the content offset for a vault slice verifying
    /// the identity bytes first.
    pub fn read_content_offset_slice(buffer: &[u8]) -> Result<u64> {
        let mut stream = Cursor::new(buffer);
        Header::read_content_offset_stream(&mut stream)
    }

    /// Read the content offset for a stream verifying
    /// the identity bytes first.
    pub fn read_content_offset_stream<R: Read + Seek>(
        stream: R,
    ) -> Result<u64> {
        let mut reader = BinaryReader::new(stream, Endian::Little);
        let identity = reader.read_bytes(VAULT_IDENTITY.len())?;
        FileIdentity::read_slice(&identity, &VAULT_IDENTITY)?;
        let header_len = reader.read_u32()? as u64;
        let content_offset = VAULT_IDENTITY.len() as u64 + 4 + header_len;
        Ok(content_offset)
    }

    /// Read the summary for a vault from a file.
    pub fn read_summary_file<P: AsRef<Path>>(file: P) -> Result<Summary> {
        let mut stream = File::open(file.as_ref())?;
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary for a slice of bytes.
    pub fn read_summary_slice(buffer: &[u8]) -> Result<Summary> {
        let mut stream = Cursor::new(buffer);
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary from a stream.
    fn read_summary_stream<R: Read + Seek>(stream: R) -> Result<Summary> {
        let mut reader = BinaryReader::new(stream, Endian::Little);

        // Read magic identity bytes
        FileIdentity::read_identity(&mut reader, &VAULT_IDENTITY)?;

        // Read in the header length
        let _ = reader.read_u32()?;

        // Read the summary
        let mut summary: Summary = Default::default();
        summary.decode(&mut reader)?;

        Ok(summary)
    }

    /// Read the header for a vault from a file.
    pub fn read_header_file<P: AsRef<Path>>(file: P) -> Result<Header> {
        let mut stream = File::open(file.as_ref())?;
        Header::read_header_stream(&mut stream)
    }

    /// Read the header from a stream.
    pub(crate) fn read_header_stream<R: Read + Seek>(
        stream: R,
    ) -> Result<Header> {
        let mut reader = BinaryReader::new(stream, Endian::Little);
        let mut header: Header = Default::default();
        header.decode(&mut reader)?;
        Ok(header)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

/// The vault contents
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Contents {
    pub(crate) data: HashMap<SecretId, VaultCommit>,
}

/// Vault file storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Vault {
    pub(crate) header: Header,
    pub(crate) contents: Contents,
}

impl Vault {
    /// Create a new vault.
    pub fn new(
        id: VaultId,
        name: String,
        algorithm: Algorithm,
        flags: VaultFlags,
    ) -> Self {
        Self {
            header: Header::new(id, name, algorithm, flags),
            contents: Default::default(),
        }
    }

    /// Get the URN for a vault identifier.
    pub fn vault_urn(id: &VaultId) -> Result<Urn> {
        let vault_urn = format!("urn:sos:vault:{}", id);
        Ok(vault_urn.parse()?)
    }

    /// Create a new vault and encode it into a buffer.
    pub fn new_buffer(
        name: Option<String>,
        passphrase: Option<SecretString>,
        seed: Option<Seed>,
    ) -> Result<(SecretString, Vault, Vec<u8>)> {
        let passphrase = if let Some(passphrase) = passphrase {
            passphrase
        } else {
            let (passphrase, _) = generate_passphrase()?;
            passphrase
        };

        let mut vault: Vault = Default::default();
        if let Some(name) = name {
            vault.set_name(name);
        }
        vault.initialize(passphrase.clone(), seed)?;
        let buffer = encode(&vault)?;
        Ok((passphrase, vault, buffer))
    }

    /// Initialize the vault with the given label and password.
    pub fn initialize(
        &mut self,
        password: SecretString,
        seed: Option<Seed>,
    ) -> Result<SecretKey> {
        if self.header.auth.salt.is_none() {
            let salt = SecretKey::generate_salt();

            let private_key = SecretKey::derive_32(
                password.expose_secret(),
                &salt,
                seed.as_ref(),
            )?;

            let default_meta: VaultMeta = Default::default();
            let meta_aead =
                self.encrypt(&private_key, &encode(&default_meta)?)?;
            self.header.set_meta(Some(meta_aead));

            // Store the salt and seed so we can generate the same
            // private key later
            self.header.auth.salt = Some(salt.to_string());
            self.header.auth.seed = seed;

            Ok(private_key)
        } else {
            Err(Error::VaultAlreadyInit)
        }
    }

    /// Set whether this vault is a default vault.
    pub fn set_default_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::DEFAULT, value);
    }

    /// Set whether this vault is an archive vault.
    pub fn set_archive_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::ARCHIVE, value);
    }

    /// Set whether this vault is an authenticator vault.
    pub fn set_authenticator_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::AUTHENTICATOR, value);
    }

    /// Set whether this vault is for contacts.
    pub fn set_contact_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::CONTACT, value);
    }

    /// Set whether this vault is for system specific information.
    pub fn set_system_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::SYSTEM, value);
    }

    /// Set whether this vault is for device specific information.
    pub fn set_device_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::DEVICE, value);
    }

    /// Set whether this vault should not sync with own devices.
    pub fn set_no_sync_self_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::NO_SYNC_SELF, value);
    }

    /// Set whether this vault should not sync with devices
    /// owned by other accounts.
    pub fn set_no_sync_other_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::NO_SYNC_OTHER, value);
    }

    /// Insert a secret into this vault.
    pub(crate) fn insert_entry(&mut self, id: SecretId, entry: VaultCommit) {
        self.contents.data.insert(id, entry);
    }

    /// Get a secret in this vault.
    pub fn get(&self, id: &SecretId) -> Option<&VaultCommit> {
        self.contents.data.get(id)
    }

    /// Encrypt plaintext using the algorithm assigned to this vault.
    pub fn encrypt(
        &self,
        key: &SecretKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self.algorithm() {
            Algorithm::XChaCha20Poly1305(_) => {
                let nonce = Nonce::new_random_24();
                xchacha20poly1305::encrypt(key, plaintext, Some(nonce))
            }
            Algorithm::AesGcm256(_) => {
                let nonce = Nonce::new_random_12();
                aesgcm256::encrypt(key, plaintext, Some(nonce))
            }
        }
    }

    /// Decrypt ciphertext using the algorithm assigned to this vault.
    pub fn decrypt(
        &self,
        key: &SecretKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self.algorithm() {
            Algorithm::XChaCha20Poly1305(_) => {
                xchacha20poly1305::decrypt(key, aead)
            }
            Algorithm::AesGcm256(_) => aesgcm256::decrypt(key, aead),
        }
    }

    /// Choose a new identifier for this vault.
    ///
    /// This is useful when importing a vault and the identifier
    /// collides with an existing vault; rather than overwriting the
    /// existing vault we can import it alongside by choosing a new
    /// identifier.
    pub fn rotate_identifier(&mut self) {
        self.header.summary.id = Uuid::new_v4();
    }

    /// Verify an encryption passphrase.
    // FIXME: use SecretString here
    pub fn verify<S: AsRef<str>>(&self, passphrase: S) -> Result<()> {
        let salt = self.salt().ok_or(Error::VaultNotInit)?;
        let meta_aead = self.header().meta().ok_or(Error::VaultNotInit)?;
        let salt = SecretKey::parse_salt(salt)?;
        let secret_key =
            SecretKey::derive_32(passphrase.as_ref(), &salt, self.seed())?;
        let _ = self
            .decrypt(&secret_key, meta_aead)
            .map_err(|_| Error::PassphraseVerification)?;
        Ok(())
    }

    /// Iterator for the secret keys and values.
    pub fn iter(&self) -> impl Iterator<Item = (&Uuid, &VaultCommit)> {
        self.contents.data.iter()
    }

    /// Iterator for the secret keys.
    pub fn keys(&self) -> impl Iterator<Item = &Uuid> {
        self.contents.data.keys()
    }

    /// Iterator for the secret values.
    pub fn values(&self) -> impl Iterator<Item = &VaultCommit> {
        self.contents.data.values()
    }

    /// Number of secrets in this vault.
    pub fn len(&self) -> usize {
        self.contents.data.len()
    }

    /// Determine if this vault is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterator for the secret keys and commit hashes.
    pub fn commits(&self) -> impl Iterator<Item = (&Uuid, &CommitHash)> {
        self.contents
            .data
            .keys()
            .zip(self.contents.data.values().map(|v| &v.0))
    }

    /// Get the salt used for passphrase authentication.
    pub fn salt(&self) -> Option<&String> {
        self.header.auth.salt.as_ref()
    }

    /// Get the seed used for passphrase authentication.
    pub fn seed(&self) -> Option<&Seed> {
        self.header.auth.seed.as_ref()
    }

    /// Get the summary for this vault.
    pub fn summary(&self) -> &Summary {
        &self.header.summary
    }

    /// Get a reference to the vault flags.
    pub fn flags(&self) -> &VaultFlags {
        self.header.summary.flags()
    }

    /// Get a mutable reference to the vault flags.
    pub fn flags_mut(&mut self) -> &mut VaultFlags {
        self.header.summary.flags_mut()
    }

    /// Get the unique identifier for this vault.
    pub fn id(&self) -> &VaultId {
        &self.header.summary.id
    }

    /// Get the public name for this vault.
    pub fn name(&self) -> &str {
        self.header.name()
    }

    /// Set the public name for this vault.
    pub fn set_name(&mut self, name: String) {
        self.header.set_name(name);
    }

    /// Get the encryption algorithm for this vault.
    pub fn algorithm(&self) -> &Algorithm {
        &self.header.summary.algorithm
    }

    /// Get the vault header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Get the mutable vault header.
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Get the meta data for all the secrets.
    pub fn meta_data(&self) -> HashMap<&Uuid, &AeadPack> {
        self.contents
            .data
            .iter()
            .map(|(k, v)| (k, &v.1 .0))
            .collect::<HashMap<_, _>>()
    }

    /// Read a vault from a file.
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vault> {
        let buffer = std::fs::read(path.as_ref())?;
        let vault: Vault = decode(&buffer)?;
        Ok(vault)
    }

    /// Write this vault to a file.
    pub fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut stream = File::create(path)?;
        let buffer = encode(self)?;
        stream.write_all(&buffer)?;
        Ok(())
    }

    /// Compute the hash of the encoded encrypted buffer for the meta and secret data.
    pub fn commit_hash(
        meta_aead: &AeadPack,
        secret_aead: &AeadPack,
    ) -> Result<(CommitHash, Vec<u8>)> {
        // Compute the hash of the encrypted and encoded bytes
        let encoded_meta = encode(meta_aead)?;
        let encoded_data = encode(secret_aead)?;
        let mut hash_bytes =
            Vec::with_capacity(encoded_meta.len() + encoded_data.len());
        hash_bytes.extend_from_slice(&encoded_meta);
        hash_bytes.extend_from_slice(&encoded_data);
        let commit = CommitHash(Sha256::hash(hash_bytes.as_slice()));
        Ok((commit, hash_bytes))
    }
}

impl From<Header> for Vault {
    fn from(header: Header) -> Self {
        Vault {
            header,
            contents: Default::default(),
        }
    }
}

impl IntoIterator for Vault {
    type Item = (SecretId, VaultCommit);
    type IntoIter =
        std::collections::hash_map::IntoIter<SecretId, VaultCommit>;

    fn into_iter(self) -> Self::IntoIter {
        self.contents.data.into_iter()
    }
}

impl VaultAccess for Vault {
    fn summary(&self) -> Result<Summary> {
        Ok(self.header.summary.clone())
    }

    fn vault_name(&self) -> Result<Cow<'_, str>> {
        Ok(Cow::Borrowed(self.name()))
    }

    fn set_vault_name(&mut self, name: String) -> Result<WriteEvent<'_>> {
        self.set_name(name.clone());
        Ok(WriteEvent::SetVaultName(Cow::Owned(name)))
    }

    fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<WriteEvent<'_>> {
        self.header.set_meta(meta_data);
        let meta = self.header.meta().cloned();
        Ok(WriteEvent::SetVaultMeta(Cow::Owned(meta)))
    }

    fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>> {
        let id = Uuid::new_v4();
        self.insert(id, commit, secret)
    }

    fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>> {
        let value = self
            .contents
            .data
            .entry(id)
            .or_insert(VaultCommit(commit, secret));
        Ok(WriteEvent::CreateSecret(id, Cow::Borrowed(value)))
    }

    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        let result = self.contents.data.get(id).map(Cow::Borrowed);
        Ok((result, ReadEvent::ReadSecret(*id)))
    }

    fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent<'_>>> {
        let _vault_id = *self.id();
        if let Some(value) = self.contents.data.get_mut(id) {
            *value = VaultCommit(commit, secret);
            Ok(Some(WriteEvent::UpdateSecret(*id, Cow::Borrowed(value))))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, id: &SecretId) -> Result<Option<WriteEvent<'_>>> {
        let entry = self.contents.data.remove(id);
        if entry.is_some() {
            Ok(Some(WriteEvent::DeleteSecret(*id)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::secret::*;

    use crate::{decode, encode, test_utils::*};

    use anyhow::Result;
    use secrecy::ExposeSecret;

    #[test]
    fn encode_decode_empty_vault() -> Result<()> {
        let vault = mock_vault();
        let buffer = encode(&vault)?;
        let decoded = decode(&buffer)?;
        assert_eq!(vault, decoded);
        Ok(())
    }

    #[test]
    fn encode_decode_secret_note() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let mut vault = mock_vault();

        // TODO: encode the salt into the header meta data

        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (secret_id, _commit, secret_meta, secret_value, _) =
            mock_vault_note(
                &mut vault,
                &encryption_key,
                secret_label,
                secret_note,
            )?;

        let buffer = encode(&vault)?;
        let decoded: Vault = decode(&buffer)?;
        assert_eq!(vault, decoded);

        let (row, _) = decoded.read(&secret_id)?;

        let value = row.unwrap();
        let VaultCommit(_, VaultEntry(row_meta, row_secret)) = value.as_ref();

        let row_meta = vault.decrypt(&encryption_key, row_meta)?;
        let row_secret = vault.decrypt(&encryption_key, row_secret)?;

        let row_meta: SecretMeta = decode(&row_meta)?;
        let row_secret: Secret = decode(&row_secret)?;

        assert_eq!(secret_meta, row_meta);
        assert_eq!(secret_value, row_secret);

        match &row_secret {
            Secret::Note { text, .. } => {
                assert_eq!(secret_note, text.expose_secret());
            }
            _ => panic!("unexpected secret type"),
        }

        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod file_tests {
    use super::*;
    use crate::{decode, test_utils::*};
    use anyhow::Result;

    #[test]
    fn decode_file() -> Result<()> {
        let (temp, _, _) = mock_vault_file()?;
        let _vault = Vault::read_file(temp.path())?;
        temp.close()?;
        Ok(())
    }

    #[test]
    fn decode_buffer() -> Result<()> {
        let (_temp, _, buffer) = mock_vault_file()?;
        let _vault: Vault = decode(&buffer)?;
        Ok(())
    }
}
