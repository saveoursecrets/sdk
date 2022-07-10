//! Vault secret storage file format.
use rs_merkle::{algorithms::Sha256, Hasher};
use serde::{Deserialize, Serialize};
use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, ReadStream,
        SeekStream, SliceStream, WriteStream,
    },
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
use uuid::Uuid;

use crate::{
    commit_tree::CommitTree,
    constants::{VAULT_EXT, VAULT_IDENTITY},
    crypto::{
        aesgcm256, algorithms::*, secret_key::SecretKey, xchacha20poly1305,
        AeadPack,
    },
    events::SyncEvent,
    iter::vault_iter,
    secret::{SecretId, VaultMeta},
    CommitHash, Error, FileIdentity, Result,
};

/// Vault version identifier.
pub const VERSION: u16 = 0;

/// Default public name for a vault.
pub const DEFAULT_VAULT_NAME: &str = "Login";

/// Mime type for vaults.
pub const MIME_TYPE_VAULT: &str = "application/sos+vault";

/// Identifier for vaults.
pub type VaultId = Uuid;

/// Type to represent a secret as an encrypted pair of meta data
/// and secret data.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry(pub AeadPack, pub AeadPack);

impl Encode for VaultEntry {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.0.encode(&mut *ser)?;
        self.1.encode(&mut *ser)?;
        Ok(())
    }
}

impl Decode for VaultEntry {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut meta: AeadPack = Default::default();
        meta.decode(&mut *de)?;
        let mut secret: AeadPack = Default::default();
        secret.decode(&mut *de)?;
        *self = VaultEntry(meta, secret);
        Ok(())
    }
}

/// Type to represent an encrypted secret with an associated commit hash.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultCommit(pub CommitHash, pub VaultEntry);

impl Encode for VaultCommit {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(self.0.as_ref())?;

        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        self.1.encode(&mut *ser)?;

        // Encode the data length for lazy iteration
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        Ok(())
    }
}

impl Decode for VaultCommit {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let commit: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;
        let commit = CommitHash(commit);

        // Read in the length of the data blob
        let _ = de.reader.read_u32()?;

        let mut group: VaultEntry = Default::default();
        group.decode(&mut *de)?;
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
    salt: Option<String>,
}

impl Encode for Auth {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.salt.serialize(&mut *ser)?;
        Ok(())
    }
}

impl Decode for Auth {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.salt = Deserialize::deserialize(&mut *de)?;
        Ok(())
    }
}

/// Summary holding basic file information such as version,
/// unique identifier and name.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Summary {
    version: u16,
    id: VaultId,
    name: String,
    #[serde(skip)]
    algorithm: Algorithm,
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
        }
    }
}

impl Summary {
    /// Create a new summary.
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
        Self {
            version: VERSION,
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
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_u16(self.version)?;
        self.algorithm.encode(&mut *ser)?;
        ser.writer.write_bytes(self.id.as_bytes())?;
        ser.writer.write_string(&self.name)?;
        Ok(())
    }
}

impl Decode for Summary {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.version = de.reader.read_u16()?;
        self.algorithm.decode(&mut *de)?;

        if !ALGORITHMS.contains(self.algorithm.as_ref()) {
            return Err(BinaryError::Boxed(Box::from(
                Error::UnknownAlgorithm(self.algorithm.into()),
            )));
        }

        let uuid: [u8; 16] =
            de.reader.read_bytes(16)?.as_slice().try_into()?;
        self.id = Uuid::from_bytes(uuid);

        self.name = de.reader.read_string()?;

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

    /// Read the content offset for a vault verifying the identity bytes first.
    pub fn read_content_offset<P: AsRef<Path>>(path: P) -> Result<usize> {
        let mut file =
            FileIdentity::read_file(path.as_ref(), &VAULT_IDENTITY)?;
        file.seek(SeekFrom::Start(VAULT_IDENTITY.len() as u64))?;

        // Header length is immediately after the identity bytes
        let mut buffer = [0; 4];
        file.read_exact(&mut buffer)?;
        let header_len = u32::from_be_bytes(buffer) as usize;
        let content_offset = VAULT_IDENTITY.len() + 4 + header_len;
        Ok(content_offset)
    }

    /// Read the summary for a vault from a file.
    pub fn read_summary_file<P: AsRef<Path>>(file: P) -> Result<Summary> {
        let mut stream = FileStream::new(file.as_ref(), OpenType::Open)?;
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary for a slice of bytes.
    pub fn read_summary_slice(buffer: &[u8]) -> Result<Summary> {
        let mut stream = SliceStream::new(buffer);
        Header::read_summary_stream(&mut stream)
    }

    /// Read the summary from a stream.
    fn read_summary_stream(stream: &mut impl ReadStream) -> Result<Summary> {
        let reader = BinaryReader::new(stream, Endian::Big);
        let mut de = Deserializer { reader };

        // Read magic identity bytes
        FileIdentity::read_identity(&mut de, &VAULT_IDENTITY)?;

        // Read in the header length
        let _ = de.reader.read_u32()?;

        // Read the summary
        let mut summary: Summary = Default::default();
        summary.decode(&mut de)?;

        Ok(summary)
    }

    /// Read the header for a vault from a file.
    pub fn read_header_file<P: AsRef<Path>>(file: P) -> Result<Header> {
        let mut stream = FileStream::new(file.as_ref(), OpenType::Open)?;
        Header::read_header_stream(&mut stream)
    }

    /// Read the header from a stream.
    pub(crate) fn read_header_stream(
        stream: &mut impl ReadStream,
    ) -> Result<Header> {
        let reader = BinaryReader::new(stream, Endian::Big);
        let mut de = Deserializer { reader };
        let mut header: Header = Default::default();
        header.decode(&mut de)?;
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
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        FileIdentity::write_identity(&mut *ser, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        self.summary.encode(&mut *ser)?;

        ser.writer.write_bool(self.meta.is_some())?;
        if let Some(meta) = &self.meta {
            meta.encode(ser)?;
        }

        self.auth.encode(&mut *ser)?;

        // Backtrack to size_pos and write new length
        let header_pos = ser.writer.tell()?;
        let header_len = header_pos - (size_pos + 4);

        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(header_len as u32)?;
        ser.writer.seek(header_pos)?;

        Ok(())
    }
}

impl Decode for Header {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        FileIdentity::read_identity(&mut *de, &VAULT_IDENTITY)
            .map_err(Box::from)?;

        // Read in the header length
        let _ = de.reader.read_u32()?;

        self.summary.decode(&mut *de)?;

        let has_meta = de.reader.read_bool()?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(de)?;
            }
        }

        self.auth.decode(&mut *de)?;
        Ok(())
    }
}

/// The vault contents
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Contents {
    data: HashMap<SecretId, VaultCommit>,
}

impl Contents {
    /// Encode a single row into a serializer.
    pub fn encode_row(
        ser: &mut Serializer,
        key: &SecretId,
        row: &VaultCommit,
    ) -> BinaryResult<()> {
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        ser.writer.write_bytes(key.as_bytes())?;
        row.encode(&mut *ser)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        ser.writer.write_u32(row_len as u32)?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub fn decode_row(
        de: &mut Deserializer,
    ) -> BinaryResult<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        let uuid: [u8; 16] =
            de.reader.read_bytes(16)?.as_slice().try_into()?;
        let uuid = Uuid::from_bytes(uuid);

        let mut row: VaultCommit = Default::default();
        row.decode(&mut *de)?;

        // Read in the row length suffix
        let _ = de.reader.read_u32()?;

        Ok((uuid, row))
    }
}

impl Encode for Contents {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        //ser.writer.write_u32(self.data.len() as u32)?;
        for (key, row) in &self.data {
            Contents::encode_row(ser, key, row)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        //let length = de.reader.read_u32()?;

        /*
        for _ in 0..length {
            let (uuid, value) = Contents::decode_row(de)?;
            self.data.insert(uuid, value);
        }
        */

        let mut pos = de.reader.tell()?;
        let len = de.reader.len()?;
        while pos < len {
            let (uuid, value) = Contents::decode_row(de)?;
            self.data.insert(uuid, value);
            pos = de.reader.tell()?;
        }

        Ok(())
    }
}

/// Vault file storage.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Vault {
    header: Header,
    contents: Contents,
}

impl Encode for Vault {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.header.encode(ser)?;
        self.contents.encode(ser)?;
        Ok(())
    }
}

impl Decode for Vault {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.header.decode(de)?;
        self.contents.decode(de)?;
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
    #[cfg(test)]
    pub(crate) fn get(&self, id: &SecretId) -> Option<&VaultCommit> {
        self.contents.data.get(id)
    }

    /// Encrypt a plaintext value using the algorithm assigned to this vault.
    pub fn encrypt(
        &self,
        key: &SecretKey,
        plaintext: &[u8],
    ) -> Result<AeadPack> {
        match self.algorithm() {
            Algorithm::XChaCha20Poly1305(_) => {
                xchacha20poly1305::encrypt(key, plaintext)
            }
            Algorithm::AesGcm256(_) => aesgcm256::encrypt(key, plaintext),
        }
    }

    /// Decrypt a ciphertext value using the algorithm assigned to this vault.
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
        let writer = BinaryWriter::new(stream, Endian::Big);
        let mut serializer = Serializer { writer };
        vault.encode(&mut serializer)?;
        Ok(())
    }

    /// Decode a vault from binary.
    pub fn decode(stream: &mut impl ReadStream) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        let reader = BinaryReader::new(stream, Endian::Big);
        let mut deserializer = Deserializer { reader };
        vault.decode(&mut deserializer)?;
        Ok(vault)
    }

    /// Read a vault from a buffer.
    pub fn read_buffer<B: AsRef<[u8]>>(buffer: B) -> Result<Vault> {
        let vault: Vault = decode(buffer.as_ref())?;
        Ok(vault)
    }

    /// Read a vault from a file.
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vault> {
        let mut stream = FileStream::new(path, OpenType::Open)?;
        Vault::decode(&mut stream)
    }

    /// Write this vault to a file.
    pub fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut stream = FileStream::new(path, OpenType::OpenAndCreate)?;
        Vault::encode(&mut stream, self)
    }

    /// Build a commit tree from the commit hashes in a vault file.
    pub fn build_tree<P: AsRef<Path>>(path: P) -> Result<CommitTree> {
        let mut commit_tree = CommitTree::new();
        let it = vault_iter(path.as_ref())?;
        for record in it {
            let record = record?;
            commit_tree.insert(record.commit());
        }
        commit_tree.commit();
        Ok(commit_tree)
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

/// Encode into a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    Ok(serde_binary::encode(encodable, Endian::Big)?)
}

/// Decode from a binary buffer.
pub fn decode<T: Decode + Default>(buffer: &[u8]) -> Result<T> {
    Ok(serde_binary::decode::<T>(buffer, Endian::Big)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::*;

    use crate::test_utils::*;

    use anyhow::Result;
    use serde_binary::binary_rw::MemoryStream;

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
                assert_eq!(secret_note, value);
            }
            _ => panic!("unexpected secret type"),
        }

        Ok(())
    }

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
