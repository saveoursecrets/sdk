use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, Decodable};

use futures::io::{AsyncReadExt, AsyncSeek};
use futures::io::{BufReader, Cursor};
use tokio_util::compat::TokioAsyncReadCompatExt;

use age::x25519::{Identity, Recipient};
use bitflags::bitflags;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow, cmp::Ordering, collections::HashMap, fmt, path::Path,
    str::FromStr,
};
use urn::Urn;
use uuid::Uuid;

use crate::{
    commit::CommitHash,
    constants::{DEFAULT_VAULT_NAME, VAULT_IDENTITY},
    crypto::{
        AccessKey, AeadPack, Cipher, Deriver, KeyDerivation, PrivateKey, Seed,
    },
    decode, encode,
    encoding::{encoding_options, VERSION},
    events::{ReadEvent, WriteEvent},
    formats::FileIdentity,
    vault::secret::SecretId,
    vfs::File,
    Error, Result, Timestamp,
};

/// Identifier for vaults.
pub type VaultId = Uuid;

bitflags! {
    /// Bit flags for a vault.
    #[derive(Default, Serialize, Deserialize)]
    pub struct VaultFlags: u64 {
        /// Indicates this vault should be treated as
        /// the default folder.
        const DEFAULT           =        0b0000000000000001;
        /// Indicates this vault is an identity vault used
        /// to authenticate a user.
        const IDENTITY          =        0b0000000000000010;
        /// Indicates this vault is to be used as an archive.
        const ARCHIVE           =        0b0000000000000100;
        /// Indicates this vault is to be used for
        /// two-factor authentication.
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
        /// Indicates this vault should not be synced with
        /// devices owned by other accounts.
        const NO_SYNC_OTHER     =        0b0000000100000000;
        /// Indicates this vault is shared using asymmetric
        /// encryption.
        const SHARED            =        0b0000001000000000;
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

    /// Determine if this vault is shared.
    pub fn is_shared(&self) -> bool {
        self.contains(VaultFlags::SHARED)
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
    pub(crate) description: String,
}

impl VaultMeta {
    /// Get the vault description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the vault description.
    pub fn set_description(&mut self, description: String) {
        self.description = description;
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
///
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait VaultAccess {
    /// Get the vault summary.
    async fn summary(&self) -> Result<Summary>;

    /// Get the name of a vault.
    async fn vault_name(&self) -> Result<Cow<'_, str>>;

    /// Set the name of a vault.
    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent<'_>>;

    /// Set the vault meta data.
    async fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<WriteEvent<'_>>;

    /// Add an encrypted secret to the vault.
    async fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>>;

    /// Insert an encrypted secret to the vault with the given id.
    ///
    /// Used internally to support consistent identifiers when
    /// mirroring in the `Gatekeeper` implementation.
    #[doc(hidden)]
    async fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>>;

    /// Get an encrypted secret from the vault.
    async fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)>;

    /// Update an encrypted secret in the vault.
    async fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent<'_>>>;

    /// Remove an encrypted secret from the vault.
    async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent<'_>>>;
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
    /// Encryption cipher.
    pub(crate) cipher: Cipher,
    /// Key derivation function.
    pub(crate) kdf: KeyDerivation,
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
            "Version {} using {} with {}\n{} {}",
            self.version, self.cipher, self.kdf, self.name, self.id
        )
    }
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            version: VERSION,
            cipher: Default::default(),
            kdf: Default::default(),
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
        cipher: Cipher,
        kdf: KeyDerivation,
        flags: VaultFlags,
    ) -> Self {
        Self {
            version: VERSION,
            cipher,
            kdf,
            id,
            name,
            flags,
        }
    }

    /// Get the version identifier.
    pub fn version(&self) -> &u16 {
        &self.version
    }

    /// Get the cipher.
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    /// Get the key derivation function.
    pub fn kdf(&self) -> &KeyDerivation {
        &self.kdf
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
    /// Information about the vault.
    pub(crate) summary: Summary,
    /// Encrypted meta data.
    pub(crate) meta: Option<AeadPack>,
    /// Additional authentication information such as
    /// the salt and seed entropy.
    pub(crate) auth: Auth,
    /// Recipients for a shared vault.
    pub(crate) shared_access: SharedAccess,
}

impl Header {
    /// Create a new header.
    pub fn new(
        id: VaultId,
        name: String,
        cipher: Cipher,
        kdf: KeyDerivation,
        flags: VaultFlags,
    ) -> Self {
        Self {
            summary: Summary::new(id, name, cipher, kdf, flags),
            meta: None,
            auth: Default::default(),
            shared_access: Default::default(),
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
    pub async fn read_content_offset<P: AsRef<Path>>(path: P) -> Result<u64> {
        let mut stream = File::open(path.as_ref()).await?.compat();
        Header::read_content_offset_stream(&mut stream).await
    }

    /// Read the content offset for a vault slice verifying
    /// the identity bytes first.
    pub async fn read_content_offset_slice(buffer: &[u8]) -> Result<u64> {
        let mut stream = BufReader::new(Cursor::new(buffer));
        Header::read_content_offset_stream(&mut stream).await
    }

    /// Read the content offset for a stream verifying
    /// the identity bytes first.
    pub async fn read_content_offset_stream<
        R: AsyncReadExt + AsyncSeek + Unpin + Send,
    >(
        stream: R,
    ) -> Result<u64> {
        let mut reader = BinaryReader::new(stream, encoding_options());
        let identity = reader.read_bytes(VAULT_IDENTITY.len()).await?;
        FileIdentity::read_slice(&identity, &VAULT_IDENTITY)?;
        let header_len = reader.read_u32().await? as u64;
        let content_offset = VAULT_IDENTITY.len() as u64 + 4 + header_len;
        Ok(content_offset)
    }

    /// Read the summary for a vault from a file.
    pub async fn read_summary_file<P: AsRef<Path>>(
        file: P,
    ) -> Result<Summary> {
        let mut stream = File::open(file.as_ref()).await?.compat();
        Header::read_summary_stream(&mut stream).await
    }

    /// Read the summary for a slice of bytes.
    pub async fn read_summary_slice(buffer: &[u8]) -> Result<Summary> {
        let mut stream = BufReader::new(Cursor::new(buffer));
        Header::read_summary_stream(&mut stream).await
    }

    /// Read the summary from a stream.
    async fn read_summary_stream<
        R: AsyncReadExt + AsyncSeek + Unpin + Send,
    >(
        stream: R,
    ) -> Result<Summary> {
        let mut reader = BinaryReader::new(stream, encoding_options());

        // Read magic identity bytes
        FileIdentity::read_identity(&mut reader, &VAULT_IDENTITY).await?;

        // Read in the header length
        let _ = reader.read_u32().await?;

        // Read the summary
        let mut summary: Summary = Default::default();
        summary.decode(&mut reader).await?;

        Ok(summary)
    }

    /// Read the header for a vault from a file.
    pub async fn read_header_file<P: AsRef<Path>>(file: P) -> Result<Header> {
        let mut stream = File::open(file.as_ref()).await?.compat();
        Header::read_header_stream(&mut stream).await
    }

    /// Read the header from a stream.
    pub(crate) async fn read_header_stream<
        R: AsyncReadExt + AsyncSeek + Unpin + Send,
    >(
        stream: R,
    ) -> Result<Header> {
        let mut reader = BinaryReader::new(stream, encoding_options());
        let mut header: Header = Default::default();
        header.decode(&mut reader).await?;
        Ok(header)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

/// Access controls for shared vaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedAccess {
    /// List of recipients for a shared vault.
    ///
    /// Every recipient is able to write to the shared vault.
    WriteAccess(Vec<String>),
    /// Private list of recipients managed by an owner.
    ///
    /// Only the owner can write to the vault, other recipients
    /// can only read.
    ReadOnly(AeadPack),
}

impl Default for SharedAccess {
    fn default() -> Self {
        Self::WriteAccess(vec![])
    }
}

impl SharedAccess {
    fn parse_recipients(access: &Vec<String>) -> Result<Vec<Recipient>> {
        let mut recipients = Vec::new();
        for recipient in access {
            let recipient = recipient.parse().map_err(|s: &str| {
                Error::InvalidX25519Identity(s.to_owned())
            })?;
            recipients.push(recipient);
        }
        Ok(recipients)
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
        cipher: Cipher,
        kdf: KeyDerivation,
        flags: VaultFlags,
    ) -> Self {
        Self {
            header: Header::new(id, name, cipher, kdf, flags),
            contents: Default::default(),
        }
    }

    /// Shared access.
    pub fn shared_access(&self) -> &SharedAccess {
        &self.header.shared_access
    }

    /// Get the URN for a vault identifier.
    pub fn vault_urn(id: &VaultId) -> Result<Urn> {
        let vault_urn = format!("urn:sos:vault:{}", id);
        Ok(vault_urn.parse()?)
    }

    /// Initialize this vault using a password for
    /// a symmetric cipher.
    pub(crate) async fn symmetric(
        &mut self,
        password: SecretString,
        seed: Option<Seed>,
    ) -> Result<PrivateKey> {
        if self.header.auth.salt.is_none() {
            let salt = KeyDerivation::generate_salt();
            let deriver = self.deriver();
            let derived_private_key =
                deriver.derive(&password, &salt, seed.as_ref())?;
            let private_key = PrivateKey::Symmetric(derived_private_key);

            // Store the salt and seed so we can derive the same
            // private key later
            self.header.auth.salt = Some(salt.to_string());
            self.header.auth.seed = seed;

            Ok(private_key)
        } else {
            Err(Error::VaultAlreadyInit)
        }
    }

    /// Initialize this vault using asymmetric encryption.
    pub(crate) async fn asymmetric(
        &mut self,
        owner: &Identity,
        mut recipients: Vec<Recipient>,
        read_only: bool,
    ) -> Result<PrivateKey> {
        if self.header.auth.salt.is_none() {
            // Ensure the owner public key is always in the list
            // of recipients
            let owner_public = owner.to_public();
            if recipients
                .iter()
                .find(|r| r.to_string() == owner_public.to_string())
                .is_none()
            {
                recipients.push(owner_public);
            }

            self.flags_mut().set(VaultFlags::SHARED, true);

            let salt = KeyDerivation::generate_salt();
            let private_key = PrivateKey::Asymmetric(owner.clone());
            self.header.summary.cipher = Cipher::X25519;

            let recipients: Vec<_> =
                recipients.into_iter().map(|r| r.to_string()).collect();

            self.header.shared_access = if read_only {
                let access = SharedAccess::WriteAccess(recipients);
                let buffer = encode(&access).await?;
                let private_key = PrivateKey::Asymmetric(owner.clone());
                let cipher = self.header.summary.cipher.clone();
                let owner_recipients = vec![owner.to_public()];
                let aead = cipher
                    .encrypt_asymmetric(
                        &private_key,
                        &buffer,
                        owner_recipients,
                    )
                    .await?;
                SharedAccess::ReadOnly(aead)
            } else {
                SharedAccess::WriteAccess(recipients)
            };

            // Store the salt so we know that the vault has
            // already been initialized, for asymmetric encryption
            // it is not used
            self.header.auth.salt = Some(salt.to_string());

            Ok(private_key)
        } else {
            Err(Error::VaultAlreadyInit)
        }
    }

    /// Key derivation function deriver.
    pub fn deriver(&self) -> Box<dyn Deriver<Sha256> + Send + 'static> {
        self.header.summary.kdf.deriver()
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

    /// Encrypt plaintext using the cipher assigned to this vault.
    pub async fn encrypt(
        &self,
        key: &PrivateKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self.cipher() {
            Cipher::XChaCha20Poly1305 | Cipher::AesGcm256 => {
                self.cipher().encrypt_symmetric(key, plaintext, None).await
            }
            Cipher::X25519 => {
                let recipients = match &self.header.shared_access {
                    SharedAccess::WriteAccess(access) => {
                        SharedAccess::parse_recipients(access)?
                    }
                    SharedAccess::ReadOnly(aead) => {
                        let buffer = self
                            .decrypt(key, aead)
                            .await
                            .map_err(|_| Error::PermissionDenied)?;
                        let shared_access: SharedAccess =
                            decode(&buffer).await?;
                        if let SharedAccess::WriteAccess(access) =
                            &shared_access
                        {
                            SharedAccess::parse_recipients(access)?
                        } else {
                            return Err(Error::PermissionDenied);
                        }
                    }
                };

                self.cipher()
                    .encrypt_asymmetric(key, plaintext, recipients)
                    .await
            }
        }
    }

    /// Decrypt ciphertext using the cipher assigned to this vault.
    pub async fn decrypt(
        &self,
        key: &PrivateKey,
        aead: &AeadPack,
    ) -> Result<Vec<u8>> {
        match self.cipher() {
            Cipher::XChaCha20Poly1305 | Cipher::AesGcm256 => {
                self.cipher().decrypt_symmetric(key, aead).await
            }
            Cipher::X25519 => {
                self.cipher().decrypt_asymmetric(key, aead).await
            }
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

    /// Verify an access key.
    pub async fn verify(&self, key: &AccessKey) -> Result<()> {
        let salt = self.salt().ok_or(Error::VaultNotInit)?;
        let meta_aead = self.header().meta().ok_or(Error::VaultNotInit)?;
        let private_key = match key {
            AccessKey::Password(password) => {
                let salt = KeyDerivation::parse_salt(salt)?;
                let deriver = self.deriver();
                PrivateKey::Symmetric(deriver.derive(
                    password,
                    &salt,
                    self.seed(),
                )?)
            }
            AccessKey::Identity(id) => PrivateKey::Asymmetric(id.clone()),
        };

        let _ = self
            .decrypt(&private_key, meta_aead)
            .await
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

    /// Get the encryption cipher for this vault.
    pub fn cipher(&self) -> &Cipher {
        &self.header.summary.cipher
    }

    /// Get the key derivation function.
    pub fn kdf(&self) -> &KeyDerivation {
        &self.header.summary.kdf
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

    /// Write this vault to a file.
    pub async fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut stream = File::create(path).await?;
        let buffer = encode(self).await?;
        stream.write_all(&buffer).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Compute the hash of the encoded encrypted buffer
    /// for the meta and secret data.
    pub async fn commit_hash(
        meta_aead: &AeadPack,
        secret_aead: &AeadPack,
    ) -> Result<(CommitHash, Vec<u8>)> {
        // Compute the hash of the encrypted and encoded bytes
        let encoded_meta = encode(meta_aead).await?;
        let encoded_data = encode(secret_aead).await?;
        let mut hash_bytes =
            Vec::with_capacity(encoded_meta.len() + encoded_data.len());
        hash_bytes.extend_from_slice(&encoded_meta);
        hash_bytes.extend_from_slice(&encoded_data);
        let commit = CommitHash(
            Sha256::digest(hash_bytes.as_slice())
                .as_slice()
                .try_into()?,
        );
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl VaultAccess for Vault {
    async fn summary(&self) -> Result<Summary> {
        Ok(self.header.summary.clone())
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>> {
        Ok(Cow::Borrowed(self.name()))
    }

    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> Result<WriteEvent<'_>> {
        self.set_name(name.clone());
        Ok(WriteEvent::SetVaultName(Cow::Owned(name)))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<WriteEvent<'_>> {
        self.header.set_meta(meta_data);
        let meta = self.header.meta().cloned();
        Ok(WriteEvent::SetVaultMeta(Cow::Owned(meta)))
    }

    async fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent<'_>> {
        let id = Uuid::new_v4();
        self.insert(id, commit, secret).await
    }

    async fn insert(
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

    async fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, ReadEvent)> {
        let result = self.contents.data.get(id).map(Cow::Borrowed);
        Ok((result, ReadEvent::ReadSecret(*id)))
    }

    async fn update(
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

    async fn delete(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent<'_>>> {
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
    use crate::{
        decode, encode,
        passwd::diceware::generate_passphrase,
        test_utils::*,
        vault::{Gatekeeper, VaultBuilder},
        Error,
    };

    use anyhow::Result;
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn vault_encode_decode_empty() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new().password(passphrase, None).await?;

        let buffer = encode(&vault).await?;
        let decoded = decode(&buffer).await?;
        assert_eq!(vault, decoded);
        Ok(())
    }

    #[tokio::test]
    async fn vault_encode_decode_secret_note() -> Result<()> {
        let (encryption_key, _, passphrase) = mock_encryption_key()?;
        let mut vault =
            VaultBuilder::new().password(passphrase, None).await?;

        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (secret_id, _commit, secret_meta, secret_value, _) =
            mock_vault_note(
                &mut vault,
                &encryption_key,
                secret_label,
                secret_note,
            )
            .await?;

        let buffer = encode(&vault).await?;

        let decoded: Vault = decode(&buffer).await?;
        assert_eq!(vault, decoded);

        let (row, _) = decoded.read(&secret_id).await?;

        let value = row.unwrap();
        let VaultCommit(_, VaultEntry(row_meta, row_secret)) = value.as_ref();

        let row_meta = vault.decrypt(&encryption_key, row_meta).await?;
        let row_secret = vault.decrypt(&encryption_key, row_secret).await?;

        let row_meta: SecretMeta = decode(&row_meta).await?;
        let row_secret: Secret = decode(&row_secret).await?;

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

    #[tokio::test]
    async fn vault_shared_folder_writable() -> Result<()> {
        set_mock_credential_builder().await;

        let owner = age::x25519::Identity::generate();
        let other_1 = age::x25519::Identity::generate();

        let mut recipients = Vec::new();
        recipients.push(other_1.to_public());

        let vault = VaultBuilder::new()
            .shared(&owner, recipients, false)
            .await?;

        // Owner adds a secret
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(AccessKey::Identity(owner.clone())).await?;
        let (meta, secret, _, _) =
            mock_secret_note("Shared label", "Shared note").await?;
        let event = keeper.create(meta.clone(), secret.clone()).await?;
        let id = if let WriteEvent::CreateSecret(id, _) = event {
            id
        } else {
            unreachable!();
        };

        // In the real world this exchange of the vault
        // would happen via a sync operation
        let vault: Vault = keeper.into();

        // Ensure recipient information is encoded properly
        let encoded = encode(&vault).await?;
        let vault: Vault = decode(&encoded).await?;

        let mut keeper_1 = Gatekeeper::new(vault, None);
        keeper_1
            .unlock(AccessKey::Identity(other_1.clone()))
            .await?;
        if let Some((read_meta, read_secret, _)) = keeper_1.read(&id).await? {
            assert_eq!(meta, read_meta);
            assert_eq!(secret, read_secret);
        } else {
            unreachable!();
        }

        let (new_meta, new_secret, _, _) =
            mock_secret_note("Shared label updated", "Shared note updated")
                .await?;
        keeper_1
            .update(&id, new_meta.clone(), new_secret.clone())
            .await?;

        // In the real world this exchange of the vault
        // would happen via a sync operation
        let vault: Vault = keeper_1.into();

        // Check the owner can see the updated secret
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(AccessKey::Identity(owner.clone())).await?;
        if let Some((read_meta, read_secret, _)) = keeper.read(&id).await? {
            assert_eq!(new_meta, read_meta);
            assert_eq!(new_secret, read_secret);
        } else {
            unreachable!();
        }

        Ok(())
    }

    #[tokio::test]
    async fn vault_shared_folder_readonly() -> Result<()> {
        set_mock_credential_builder().await;

        let owner = age::x25519::Identity::generate();
        let other_1 = age::x25519::Identity::generate();

        let mut recipients = Vec::new();
        recipients.push(other_1.to_public());

        let vault =
            VaultBuilder::new().shared(&owner, recipients, true).await?;

        // Owner adds a secret
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(AccessKey::Identity(owner.clone())).await?;
        let (meta, secret, _, _) =
            mock_secret_note("Shared label", "Shared note").await?;
        let event = keeper.create(meta.clone(), secret.clone()).await?;
        let id = if let WriteEvent::CreateSecret(id, _) = event {
            id
        } else {
            unreachable!();
        };

        // Check the owner can update
        let (new_meta, new_secret, _, _) =
            mock_secret_note("Shared label updated", "Shared note updated")
                .await?;
        keeper
            .update(&id, new_meta.clone(), new_secret.clone())
            .await?;

        // In the real world this exchange of the vault
        // would happen via a sync operation
        let vault: Vault = keeper.into();

        // Ensure recipient information is encoded properly
        let encoded = encode(&vault).await?;
        let vault: Vault = decode(&encoded).await?;

        let mut keeper_1 = Gatekeeper::new(vault, None);
        keeper_1
            .unlock(AccessKey::Identity(other_1.clone()))
            .await?;

        // Other recipient can read the secret
        if let Some((read_meta, read_secret, _)) = keeper_1.read(&id).await? {
            assert_eq!(new_meta, read_meta);
            assert_eq!(new_secret, read_secret);
        } else {
            unreachable!();
        }

        //  If the other recipient tries to update
        //  they get a permission denied error
        let (updated_meta, updated_secret, _, _) = mock_secret_note(
            "Shared label update denied",
            "Shared note update denied",
        )
        .await?;
        let result = keeper_1
            .update(&id, updated_meta.clone(), updated_secret.clone())
            .await;
        assert!(matches!(result, Err(Error::PermissionDenied)));

        // Trying to create a secret is also denied
        let result = keeper_1
            .create(updated_meta.clone(), updated_secret.clone())
            .await;
        assert!(matches!(result, Err(Error::PermissionDenied)));

        // Trying to delete a secret is also denied
        let result = keeper_1.delete(&id).await;
        assert!(matches!(result, Err(Error::PermissionDenied)));

        Ok(())
    }
}
