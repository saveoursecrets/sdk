//! Vault secret storage file format.
use rs_merkle::{algorithms::Sha256, Hasher};
use serde::{Deserialize, Serialize};

use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
    Endian, FileStream, ReadStream, SeekStream, SliceStream, WriteStream,
};

use secrecy::{ExposeSecret, SecretString};
use std::{
    borrow::Cow, cmp::Ordering, collections::HashMap, fmt, fs::File,
    path::Path,
};
use uuid::Uuid;

use crate::{
    constants::{
        DEFAULT_VAULT_NAME, VAULT_EXT, VAULT_IDENTITY, VAULT_VERSION,
    },
    crypto::{
        aesgcm256, algorithms::*, secret_key::SecretKey, xchacha20poly1305,
        AeadPack, Nonce,
    },
    decode, encode,
    events::SyncEvent,
    generate_passphrase,
    secret::{SecretId, VaultMeta},
    CommitHash, Error, FileIdentity, Result,
};

/// Identifier for vaults.
pub type VaultId = Uuid;

/// Type to represent a secret as an encrypted pair of meta data
/// and secret data.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry(pub AeadPack, pub AeadPack);

impl Encode for VaultEntry {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        self.0.encode(&mut *writer)?;
        self.1.encode(&mut *writer)?;
        Ok(())
    }
}

impl Decode for VaultEntry {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let mut meta: AeadPack = Default::default();
        meta.decode(&mut *reader)?;
        let mut secret: AeadPack = Default::default();
        secret.decode(&mut *reader)?;
        *self = VaultEntry(meta, secret);
        Ok(())
    }
}

/// Type to represent an encrypted secret with an associated commit hash.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultCommit(pub CommitHash, pub VaultEntry);

impl Encode for VaultCommit {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(self.0.as_ref())?;

        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        self.1.encode(&mut *writer)?;

        // Encode the data length for lazy iteration
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        Ok(())
    }
}

impl Decode for VaultCommit {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let commit: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        let commit = CommitHash(commit);

        // Read in the length of the data blob
        let _ = reader.read_u32()?;

        let mut group: VaultEntry = Default::default();
        group.decode(&mut *reader)?;
        self.0 = commit;
        self.1 = group;
        Ok(())
    }
}

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
    fn vault_name<'a>(&'a self) -> Result<Cow<'a, str>>;

    /// Set the name of a vault.
    fn set_vault_name(&mut self, name: String) -> Result<SyncEvent<'_>>;

    /// Set the vault meta data.
    fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<SyncEvent<'_>>;

    /// Add an encrypted secret to the vault.
    fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<SyncEvent<'_>>;

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
    ) -> Result<SyncEvent<'_>>;

    /// Get an encrypted secret from the vault.
    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, SyncEvent<'_>)>;

    /// Update an encrypted secret in the vault.
    fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<SyncEvent<'_>>>;

    /// Remove an encrypted secret from the vault.
    fn delete(&mut self, id: &SecretId) -> Result<Option<SyncEvent<'_>>>;
}

/// Authentication information.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Auth {
    /// Salt used to derive a secret key from the passphrase.
    salt: Option<String>,
}

impl Encode for Auth {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bool(self.salt.is_some())?;
        if let Some(salt) = &self.salt {
            writer.write_string(salt)?;
        }
        Ok(())
    }
}

impl Decode for Auth {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let has_salt = reader.read_bool()?;
        if has_salt {
            self.salt = Some(reader.read_string()?);
        }
        Ok(())
    }
}

/// Summary holding basic file information such as version,
/// unique identifier and name.
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub struct Summary {
    /// Encoding version.
    version: u16,
    /// Unique identifier for the vault.
    id: VaultId,
    /// Vault name.
    name: String,
    /// Encryption algorithm.
    #[serde(skip)]
    algorithm: Algorithm,
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
            version: VAULT_VERSION,
            algorithm: Default::default(),
            id: Uuid::new_v4(),
            name: DEFAULT_VAULT_NAME.to_string(),
        }
    }
}

impl Summary {
    /// Create a new summary.
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
        Self {
            version: VAULT_VERSION,
            algorithm,
            id,
            name,
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
}

impl Encode for Summary {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_u16(self.version)?;
        self.algorithm.encode(&mut *writer)?;
        writer.write_bytes(self.id.as_bytes())?;
        writer.write_string(&self.name)?;
        Ok(())
    }
}

impl Decode for Summary {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.version = reader.read_u16()?;
        self.algorithm.decode(&mut *reader)?;

        if !ALGORITHMS.contains(self.algorithm.as_ref()) {
            return Err(BinaryError::Boxed(Box::from(
                Error::UnknownAlgorithm(self.algorithm.into()),
            )));
        }

        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        self.id = Uuid::from_bytes(uuid);
        self.name = reader.read_string()?;
        Ok(())
    }
}

/// File header, identifier and version information
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    summary: Summary,
    meta: Option<AeadPack>,
    auth: Auth,
}

impl Header {
    /// Create a new header.
    pub fn new(id: VaultId, name: String, algorithm: Algorithm) -> Self {
        Self {
            summary: Summary::new(id, name, algorithm),
            meta: None,
            auth: Default::default(),
        }
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
        let mut stream = FileStream(File::open(path.as_ref())?);
        Header::read_content_offset_stream(&mut stream)
    }

    /// Read the content offset for a vault slice verifying
    /// the identity bytes first.
    pub fn read_content_offset_slice(buffer: &[u8]) -> Result<u64> {
        let mut stream = SliceStream::new(buffer);
        Header::read_content_offset_stream(&mut stream)
    }

    /// Read the content offset for a stream verifying
    /// the identity bytes first.
    pub fn read_content_offset_stream(
        stream: &mut dyn ReadStream,
    ) -> Result<u64> {
        let mut reader = BinaryReader::new(stream, Endian::Big);
        let identity = reader.read_bytes(VAULT_IDENTITY.len())?;
        FileIdentity::read_slice(&identity, &VAULT_IDENTITY)?;
        let header_len = reader.read_u32()? as u64;
        let content_offset = VAULT_IDENTITY.len() as u64 + 4 + header_len;
        Ok(content_offset)
    }

    /// Read the summary for a vault from a file.
    pub fn read_summary_file<P: AsRef<Path>>(file: P) -> Result<Summary> {
        let mut stream = FileStream(File::open(file.as_ref())?);
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary for a slice of bytes.
    pub fn read_summary_slice(buffer: &[u8]) -> Result<Summary> {
        let mut stream = SliceStream::new(buffer);
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary from a stream.
    fn read_summary_stream(stream: &mut impl ReadStream) -> Result<Summary> {
        let mut reader = BinaryReader::new(stream, Endian::Big);

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
        let mut stream = FileStream(File::open(file.as_ref())?);
        Header::read_header_stream(&mut stream)
    }

    /// Read the header from a stream.
    pub(crate) fn read_header_stream(
        stream: &mut impl ReadStream,
    ) -> Result<Header> {
        let mut reader = BinaryReader::new(stream, Endian::Big);
        let mut header: Header = Default::default();
        header.decode(&mut reader)?;
        Ok(header)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            summary: Default::default(),
            meta: None,
            auth: Default::default(),
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

impl Encode for Header {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        FileIdentity::write_identity(&mut *writer, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        self.summary.encode(&mut *writer)?;

        writer.write_bool(self.meta.is_some())?;
        if let Some(meta) = &self.meta {
            meta.encode(&mut *writer)?;
        }

        self.auth.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let header_pos = writer.tell()?;
        let header_len = header_pos - (size_pos + 4);

        writer.seek(size_pos)?;
        writer.write_u32(header_len as u32)?;
        writer.seek(header_pos)?;

        Ok(())
    }
}

impl Decode for Header {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        FileIdentity::read_identity(&mut *reader, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        // Read in the header length
        let _ = reader.read_u32()?;

        self.summary.decode(&mut *reader)?;

        let has_meta = reader.read_bool()?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(&mut *reader)?;
            }
        }

        self.auth.decode(&mut *reader)?;
        Ok(())
    }
}

/// The vault contents
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Contents {
    data: HashMap<SecretId, VaultCommit>,
}

impl Contents {
    /// Encode a single row into a serializer.
    pub fn encode_row(
        writer: &mut BinaryWriter,
        key: &SecretId,
        row: &VaultCommit,
    ) -> BinaryResult<()> {
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        writer.write_bytes(key.as_bytes())?;
        row.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32)?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub fn decode_row(
        reader: &mut BinaryReader,
    ) -> BinaryResult<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = reader.read_u32()?;

        let uuid: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        let uuid = Uuid::from_bytes(uuid);

        let mut row: VaultCommit = Default::default();
        row.decode(&mut *reader)?;

        // Read in the row length suffix
        let _ = reader.read_u32()?;

        Ok((uuid, row))
    }
}

impl Encode for Contents {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        //ser.writer.write_u32(self.data.len() as u32)?;
        for (key, row) in &self.data {
            Contents::encode_row(writer, key, row)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        //let length = de.reader.read_u32()?;

        /*
        for _ in 0..length {
            let (uuid, value) = Contents::decode_row(de)?;
            self.data.insert(uuid, value);
        }
        */

        let mut pos = reader.tell()?;
        let len = reader.len()?;
        while pos < len {
            let (uuid, value) = Contents::decode_row(reader)?;
            self.data.insert(uuid, value);
            pos = reader.tell()?;
        }

        Ok(())
    }
}

/// Vault file storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Vault {
    header: Header,
    contents: Contents,
}

impl Encode for Vault {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        self.header.encode(writer)?;
        self.contents.encode(writer)?;
        Ok(())
    }
}

impl Decode for Vault {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.header.decode(reader)?;
        self.contents.decode(reader)?;
        Ok(())
    }
}

impl Vault {
    /// Create a new vault.
    pub fn new(id: VaultId, name: String, algorithm: Algorithm) -> Self {
        Self {
            header: Header::new(id, name, algorithm),
            contents: Default::default(),
        }
    }

    /// Create a new vault and encode it into a buffer.
    pub fn new_buffer(
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Vault, Vec<u8>)> {
        let passphrase = if let Some(passphrase) = passphrase {
            secrecy::Secret::new(passphrase)
        } else {
            let (passphrase, _) = generate_passphrase()?;
            passphrase
        };
        let mut vault: Vault = Default::default();
        if let Some(name) = name {
            vault.set_name(name);
        }
        vault.initialize(passphrase.expose_secret())?;
        let buffer = encode(&vault)?;
        Ok((passphrase, vault, buffer))
    }

    /// Initialize the vault with the given label and password.
    pub fn initialize<S: AsRef<str>>(
        &mut self,
        password: S,
    ) -> Result<SecretKey> {
        if self.header.auth.salt.is_none() {
            let salt = SecretKey::generate_salt();
            let private_key = SecretKey::derive_32(password, &salt)?;

            // Store the salt so we can generate the same
            // private key later
            self.header.auth.salt = Some(salt.to_string());

            let default_meta: VaultMeta = Default::default();
            let meta_aead =
                self.encrypt(&private_key, &encode(&default_meta)?)?;
            self.header.set_meta(Some(meta_aead));
            Ok(private_key)
        } else {
            Err(Error::VaultAlreadyInit)
        }
    }

    /// Insert a secret into this vault.
    pub(crate) fn insert_entry(&mut self, id: SecretId, entry: VaultCommit) {
        self.contents.data.insert(id, entry);
    }

    /// Get a secret in this vault.
    pub fn get(&self, id: &SecretId) -> Option<&VaultCommit> {
        self.contents.data.get(id)
    }

    /// Implements nonce-reuse protection by scanning all
    /// existing nonces and recursing if a collision is found.
    fn generate_safe_nonce(&self) -> Nonce {
        let nonce = match self.algorithm() {
            Algorithm::AesGcm256(_) => Nonce::new_random_12(),
            Algorithm::XChaCha20Poly1305(_) => Nonce::new_random_24(),
        };

        if let Some(vault_meta) = self.header().meta() {
            // Got collision, try again
            if nonce == vault_meta.nonce {
                return self.generate_safe_nonce();
            }
        }

        for VaultCommit(_, VaultEntry(meta, data)) in self.values() {
            if nonce == meta.nonce {
                // Got collision, try again
                return self.generate_safe_nonce();
            }
            if nonce == data.nonce {
                // Got collision, try again
                return self.generate_safe_nonce();
            }
        }
        nonce
    }

    /// Encrypt plaintext using the algorithm assigned to this vault.
    pub fn encrypt(
        &self,
        key: &SecretKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self.algorithm() {
            Algorithm::XChaCha20Poly1305(_) => {
                let nonce = self.generate_safe_nonce();
                xchacha20poly1305::encrypt(key, plaintext, Some(nonce))
            }
            Algorithm::AesGcm256(_) => {
                let nonce = self.generate_safe_nonce();
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

    /// Verify an encryption passphrase.
    pub fn verify<S: AsRef<str>>(&self, passphrase: S) -> Result<()> {
        let salt = self.salt().ok_or(Error::VaultNotInit)?;
        let meta_aead = self.header().meta().ok_or(Error::VaultNotInit)?;
        let salt = SecretKey::parse_salt(salt)?;
        let secret_key = SecretKey::derive_32(passphrase.as_ref(), &salt)?;
        let _ = self.decrypt(&secret_key, &meta_aead)?;
        Ok(())
    }

    /// Iterator for the secret keys and values.
    pub fn iter<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a Uuid, &'a VaultCommit)> {
        self.contents.data.iter()
    }

    /// Iterator for the secret keys.
    pub fn keys<'a>(&'a self) -> impl Iterator<Item = &'a Uuid> {
        self.contents.data.keys()
    }

    /// Iterator for the secret values.
    pub fn values<'a>(&'a self) -> impl Iterator<Item = &'a VaultCommit> {
        self.contents.data.values()
    }

    /// Number of secrets in this vault.
    pub fn len(&self) -> usize {
        self.contents.data.len()
    }

    /// Iterator for the secret keys and commit hashes.
    pub fn commits<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a Uuid, &'a CommitHash)> {
        self.contents
            .data
            .keys()
            .zip(self.contents.data.values().map(|v| &v.0))
    }

    /// Get the salt used for passphrase authentication.
    pub fn salt(&self) -> Option<&String> {
        self.header.auth.salt.as_ref()
    }

    /// The file extension for vault files.
    pub fn extension() -> &'static str {
        VAULT_EXT
    }

    /// Get the summary for this vault.
    pub fn summary(&self) -> &Summary {
        &self.header.summary
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

    /// Encode a vault to binary.
    pub fn encode(
        stream: &mut impl WriteStream,
        vault: &Vault,
    ) -> Result<()> {
        let mut writer = BinaryWriter::new(stream, Endian::Big);
        vault.encode(&mut writer)?;
        Ok(())
    }

    /// Decode a vault from binary.
    pub fn decode(stream: &mut impl ReadStream) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        let mut reader = BinaryReader::new(stream, Endian::Big);
        vault.decode(&mut reader)?;
        Ok(vault)
    }

    /// Read a vault from a buffer.
    pub fn read_buffer<B: AsRef<[u8]>>(buffer: B) -> Result<Vault> {
        let vault: Vault = decode(buffer.as_ref())?;
        Ok(vault)
    }

    /// Read a vault from a file.
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vault> {
        let mut stream = FileStream(File::open(path)?);
        Vault::decode(&mut stream)
    }

    /// Write this vault to a file.
    pub fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut stream = FileStream(File::create(path)?);
        Vault::encode(&mut stream, self)
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

    fn vault_name<'a>(&'a self) -> Result<Cow<'a, str>> {
        Ok(Cow::Borrowed(self.name()))
    }

    fn set_vault_name(&mut self, name: String) -> Result<SyncEvent<'_>> {
        self.set_name(name.clone());
        Ok(SyncEvent::SetVaultName(Cow::Owned(name)))
    }

    fn set_vault_meta(
        &mut self,
        meta_data: Option<AeadPack>,
    ) -> Result<SyncEvent<'_>> {
        self.header.set_meta(meta_data);
        let meta = self.header.meta().map(|m| m.clone());
        Ok(SyncEvent::SetVaultMeta(Cow::Owned(meta)))
    }

    fn create(
        &mut self,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<SyncEvent<'_>> {
        let id = Uuid::new_v4();
        self.insert(id, commit, secret)
    }

    fn insert(
        &mut self,
        id: SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<SyncEvent<'_>> {
        let value = self
            .contents
            .data
            .entry(id)
            .or_insert(VaultCommit(commit, secret));
        Ok(SyncEvent::CreateSecret(id, Cow::Borrowed(value)))
    }

    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, VaultCommit>>, SyncEvent<'_>)> {
        let result = self.contents.data.get(id).map(Cow::Borrowed);
        Ok((result, SyncEvent::ReadSecret(*id)))
    }

    fn update(
        &mut self,
        id: &SecretId,
        commit: CommitHash,
        secret: VaultEntry,
    ) -> Result<Option<SyncEvent<'_>>> {
        if let Some(value) = self.contents.data.get_mut(id) {
            *value = VaultCommit(commit, secret);

            Ok(Some(SyncEvent::UpdateSecret(*id, Cow::Borrowed(value))))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, id: &SecretId) -> Result<Option<SyncEvent<'_>>> {
        let entry = self.contents.data.remove(id);
        if entry.is_some() {
            Ok(Some(SyncEvent::DeleteSecret(*id)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::*;

    use crate::test_utils::*;

    use anyhow::Result;
    use binary_stream::MemoryStream;
    use secrecy::ExposeSecret;

    #[test]
    fn encode_decode_empty_vault() -> Result<()> {
        let vault = mock_vault();
        let mut stream = MemoryStream::new();
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
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

        let mut stream = MemoryStream::new();
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
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
            Secret::Note(value) => {
                assert_eq!(secret_note, value.expose_secret());
            }
            _ => panic!("unexpected secret type"),
        }

        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod file_tests {
    use super::*;
    use crate::test_utils::*;
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
