use crate::{Error, Result};
use age::x25519::{Identity, Recipient};
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, Decodable};
use indexmap::IndexMap;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sos_core::{
    commit::CommitHash,
    constants::{DEFAULT_VAULT_NAME, URN_NID, VAULT_IDENTITY, VAULT_NSS},
    crypto::{
        AccessKey, AeadPack, Cipher, Deriver, KeyDerivation, PrivateKey, Seed,
    },
    decode, encode,
    encoding::{encoding_options, VERSION},
    events::{ReadEvent, WriteEvent},
    file_identity::FileIdentity,
    AuthenticationError, SecretId, UtcDateTime, VaultCommit, VaultEntry,
    VaultFlags, VaultId,
};
use sos_vfs::File;
use std::io::Cursor;
use std::{
    borrow::Cow, cmp::Ordering, collections::HashMap, fmt, path::Path,
};
use tokio::io::{AsyncReadExt, AsyncSeek, BufReader};
use typeshare::typeshare;
use urn::Urn;
use uuid::Uuid;

/// Vault meta data.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    /// Date created timestamp.
    pub(crate) date_created: UtcDateTime,
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
    pub fn date_created(&self) -> &UtcDateTime {
        &self.date_created
    }
}

/// Read and write encrypted data to a vault.
///
/// The storage may be in-memory, backed by a file on disc or another
/// destination for the encrypted bytes.
///
/// Uses `Cow` smart pointers because when we are reading
/// from an in-memory `Vault` we can return references whereas
/// other containers such as file access would return owned data.
#[async_trait]
pub trait EncryptedEntry {
    /// Error type for vault access.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<sos_core::Error>
        + Send
        + Sync
        + 'static;

    /// Get the vault summary.
    async fn summary(&self) -> std::result::Result<Summary, Self::Error>;

    /// Get the name of a vault.
    async fn vault_name(
        &self,
    ) -> std::result::Result<Cow<'_, str>, Self::Error>;

    /// Set the name of a vault.
    async fn set_vault_name(
        &mut self,
        name: String,
    ) -> std::result::Result<WriteEvent, Self::Error>;

    /// Set the flags for a vault.
    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> std::result::Result<WriteEvent, Self::Error>;

    /// Set the vault meta data.
    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> std::result::Result<WriteEvent, Self::Error>;

    /// Add an encrypted secret to the vault.
    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> std::result::Result<WriteEvent, Self::Error>;

    /// Insert an encrypted secret to the vault with the given id.
    ///
    /// Used internally to support consistent identifiers when
    /// mirroring in the `AccessPoint` implementation.
    #[doc(hidden)]
    async fn insert_secret(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> std::result::Result<WriteEvent, Self::Error>;

    /// Get an encrypted secret from the vault.
    async fn read_secret<'a>(
        &'a self,
        id: &SecretId,
    ) -> std::result::Result<
        Option<(Cow<'a, VaultCommit>, ReadEvent)>,
        Self::Error,
    >;

    /// Update an encrypted secret in the vault.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> std::result::Result<Option<WriteEvent>, Self::Error>;

    /// Remove an encrypted secret from the vault.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> std::result::Result<Option<WriteEvent>, Self::Error>;

    /// Replace the vault with new vault content.
    async fn replace_vault(
        &mut self,
        vault: &Vault,
    ) -> std::result::Result<(), Self::Error>;
}

/// Authentication information.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    /// Salt used to derive a secret key from the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) salt: Option<String>,
    /// Additional entropy to concatenate with the password
    /// before deriving the secret key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seed: Option<Seed>,
}

/// Summary holding basic file information such as version,
/// unique identifier and name.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
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
        version: u16,
        id: VaultId,
        name: String,
        cipher: Cipher,
        kdf: KeyDerivation,
        flags: VaultFlags,
    ) -> Self {
        Self {
            version,
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

    /// Encryption cipher.
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    /// Key derivation function.
    pub fn kdf(&self) -> &KeyDerivation {
        &self.kdf
    }

    /// Vault identifier.
    pub fn id(&self) -> &VaultId {
        &self.id
    }

    /// Public name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the public name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Vault flags.
    pub fn flags(&self) -> &VaultFlags {
        &self.flags
    }

    /// Mutable reference to the vault flags.
    pub fn flags_mut(&mut self) -> &mut VaultFlags {
        &mut self.flags
    }
}

impl From<Summary> for VaultId {
    fn from(value: Summary) -> Self {
        value.id
    }
}

impl From<Summary> for Header {
    fn from(value: Summary) -> Self {
        Header::new(
            value.id,
            value.name,
            value.cipher,
            value.kdf,
            value.flags,
        )
    }
}

impl From<Summary> for Vault {
    fn from(value: Summary) -> Self {
        let mut vault: Vault = Default::default();
        vault.header = value.into();
        vault
    }
}

/// File header, identifier and version information
#[derive(Serialize, Deserialize, Clone, Default, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Information about the vault.
    pub(crate) summary: Summary,
    /// Encrypted meta data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) meta: Option<AeadPack>,
    /// Additional authentication information such as
    /// the salt and seed entropy.
    pub(crate) auth: Auth,
    /// Recipients for a shared vault.
    #[serde(default, skip_serializing_if = "SharedAccess::is_empty")]
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
            summary: Summary::new(VERSION, id, name, cipher, kdf, flags),
            meta: None,
            auth: Default::default(),
            shared_access: Default::default(),
        }
    }

    /// Vault identifier.
    pub fn id(&self) -> &VaultId {
        self.summary.id()
    }

    /// Mutable identifier for this vault.
    pub fn id_mut(&mut self) -> &mut VaultId {
        &mut self.summary.id
    }

    /// Reference to the vault flags.
    pub fn flags(&self) -> &VaultFlags {
        self.summary.flags()
    }

    /// Mutable reference to the vault flags.
    pub fn flags_mut(&mut self) -> &mut VaultFlags {
        self.summary.flags_mut()
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

    /// Set the salt for key derivation.
    pub fn set_salt(&mut self, salt: Option<String>) {
        self.auth.salt = salt;
    }

    /// Get the encrypted meta data for the vault.
    pub fn meta(&self) -> Option<&AeadPack> {
        self.meta.as_ref()
    }

    /// Set the encrypted meta data for the vault.
    pub fn set_meta(&mut self, meta: Option<AeadPack>) {
        self.meta = meta;
    }

    /// Set the seed entropy for key derivation.
    pub fn set_seed(&mut self, seed: Option<Seed>) {
        self.auth.seed = seed;
    }

    /// Read the content offset for a vault file verifying
    /// the identity bytes first.
    pub async fn read_content_offset<P: AsRef<Path>>(path: P) -> Result<u64> {
        let mut stream = File::open(path.as_ref()).await?;
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
        let mut stream = File::open(file.as_ref()).await?;
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
        let mut stream = File::open(file.as_ref()).await?;
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SharedAccess {
    /// List of recipients for a shared vault.
    ///
    /// Every recipient is able to write to the shared vault.
    #[serde(rename = "write")]
    WriteAccess(Vec<String>),
    /// Private list of recipients managed by an owner.
    ///
    /// Only the owner can write to the vault, other recipients
    /// can only read.
    #[serde(rename = "read")]
    ReadOnly(AeadPack),
}

impl Default for SharedAccess {
    fn default() -> Self {
        Self::WriteAccess(vec![])
    }
}

impl SharedAccess {
    /// Determine if the shared access configuration is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::WriteAccess(recipients) => recipients.is_empty(),
            Self::ReadOnly(_) => false,
        }
    }

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
#[doc(hidden)]
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct Contents {
    #[serde(flatten)]
    pub(crate) data: IndexMap<SecretId, VaultCommit>,
}

/// Vault file storage.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
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
        // FIXME: use UrnBuilder
        let vault_urn = format!("urn:{}:{}{}", URN_NID, VAULT_NSS, id);
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
            if !recipients
                .iter()
                .any(|r| r.to_string() == owner_public.to_string())
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
    pub fn set_no_sync_flag(&mut self, value: bool) {
        self.flags_mut().set(VaultFlags::NO_SYNC, value);
    }

    /// Insert a secret into this vault.
    pub fn insert_entry(&mut self, id: SecretId, entry: VaultCommit) {
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
            Cipher::XChaCha20Poly1305 | Cipher::AesGcm256 => Ok(self
                .cipher()
                .encrypt_symmetric(key, plaintext, None)
                .await?),
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

                Ok(self
                    .cipher()
                    .encrypt_asymmetric(key, plaintext, recipients)
                    .await?)
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
                Ok(self.cipher().decrypt_symmetric(key, aead).await?)
            }
            Cipher::X25519 => {
                Ok(self.cipher().decrypt_asymmetric(key, aead).await?)
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
            .map_err(|_| AuthenticationError::PasswordVerification)?;

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

    /// Convert this vault into a create vault event.
    ///
    /// Ensures the vault is head-only before encoding into the event.
    pub async fn into_event(&self) -> Result<WriteEvent> {
        let buffer = if self.is_empty() {
            encode(self).await?
        } else {
            let header = self.header.clone();
            let vault: Vault = header.into();
            encode(&vault).await?
        };
        Ok(WriteEvent::CreateVault(buffer))
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

    /// Reference to the vault flags.
    pub fn flags(&self) -> &VaultFlags {
        self.header.flags()
    }

    /// Mutable reference to the vault flags.
    pub fn flags_mut(&mut self) -> &mut VaultFlags {
        self.header.flags_mut()
    }

    /// Unique identifier for this vault.
    pub fn id(&self) -> &VaultId {
        &self.header.summary.id
    }

    /// Public name for this vault.
    pub fn name(&self) -> &str {
        self.header.name()
    }

    /// Set the public name of this vault.
    pub fn set_name(&mut self, name: String) {
        self.header.set_name(name);
    }

    /// Encryption cipher for this vault.
    pub fn cipher(&self) -> &Cipher {
        &self.header.summary.cipher
    }

    /// Key derivation function.
    pub fn kdf(&self) -> &KeyDerivation {
        &self.header.summary.kdf
    }

    /// Vault header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Mutable vault header.
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Vault data.
    pub fn data(&self) -> &IndexMap<SecretId, VaultCommit> {
        &self.contents.data
    }

    /// Mutable vault data.
    pub fn data_mut(&mut self) -> &mut IndexMap<SecretId, VaultCommit> {
        &mut self.contents.data
    }

    /// Get the meta data for all the secrets.
    pub fn meta_data(&self) -> HashMap<&Uuid, &AeadPack> {
        self.contents
            .data
            .iter()
            .map(|(k, v)| (k, &v.1 .0))
            .collect::<HashMap<_, _>>()
    }

    /// Compute the hash of the encoded encrypted buffer
    /// for the meta and secret data.
    #[doc(hidden)]
    pub async fn commit_hash(
        meta_aead: &AeadPack,
        secret_aead: &AeadPack,
    ) -> Result<CommitHash> {
        // Compute the hash of the encrypted and encoded bytes
        let encoded_meta = encode(meta_aead).await?;
        let encoded_data = encode(secret_aead).await?;

        let mut hasher = Sha256::new();
        hasher.update(&encoded_meta);
        hasher.update(&encoded_data);
        let digest = hasher.finalize();
        Ok(CommitHash(digest.as_slice().try_into()?))
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

impl From<Vault> for Header {
    fn from(value: Vault) -> Self {
        value.header
    }
}

impl IntoIterator for Vault {
    type Item = (SecretId, VaultCommit);
    type IntoIter = indexmap::map::IntoIter<SecretId, VaultCommit>;

    fn into_iter(self) -> Self::IntoIter {
        self.contents.data.into_iter()
    }
}

#[async_trait]
impl EncryptedEntry for Vault {
    type Error = Error;

    async fn summary(&self) -> Result<Summary> {
        Ok(self.header.summary.clone())
    }

    async fn vault_name(&self) -> Result<Cow<'_, str>> {
        Ok(Cow::Borrowed(self.name()))
    }

    async fn set_vault_name(&mut self, name: String) -> Result<WriteEvent> {
        self.set_name(name.clone());
        Ok(WriteEvent::SetVaultName(name))
    }

    async fn set_vault_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        *self.header.flags_mut() = flags.clone();
        Ok(WriteEvent::SetVaultFlags(flags))
    }

    async fn set_vault_meta(
        &mut self,
        meta_data: AeadPack,
    ) -> Result<WriteEvent> {
        self.header.set_meta(Some(meta_data.clone()));
        Ok(WriteEvent::SetVaultMeta(meta_data))
    }

    async fn create_secret(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        let id = Uuid::new_v4();
        self.insert_secret(id, commit, secret).await
    }

    async fn insert_secret(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<WriteEvent> {
        let value = self
            .contents
            .data
            .entry(id)
            .or_insert(VaultCommit(commit, secret));
        Ok(WriteEvent::CreateSecret(id, value.clone()))
    }

    async fn read_secret<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<Option<(Cow<'a, VaultCommit>, ReadEvent)>> {
        let result = self
            .contents
            .data
            .get(id)
            .map(|c| (Cow::Borrowed(c), ReadEvent::ReadSecret(*id)));
        Ok(result)
    }

    async fn update_secret(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<WriteEvent>> {
        let _vault_id = *self.id();
        if let Some(value) = self.contents.data.get_mut(id) {
            *value = VaultCommit(commit, secret);
            Ok(Some(WriteEvent::UpdateSecret(*id, value.clone())))
        } else {
            Ok(None)
        }
    }

    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        let entry = self.contents.data.shift_remove(id);
        Ok(entry.map(|_| WriteEvent::DeleteSecret(*id)))
    }

    async fn replace_vault(&mut self, vault: &Vault) -> Result<()> {
        *self = vault.clone();
        Ok(())
    }
}
