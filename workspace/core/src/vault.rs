//! Vault secret storage file format.
use serde::{Deserialize, Serialize};
use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, ReadStream,
        SeekStream, SliceStream, WriteStream,
    },
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::{borrow::Cow, collections::HashMap, path::Path};
use uuid::Uuid;

use crate::{
    crypto::{
        aesgcm256, algorithms::*, secret_key::SecretKey, xchacha20poly1305,
        AeadPack,
    },
    file_identity::FileIdentity,
    operations::{Payload, VaultAccess},
    secret::{SecretId, VaultMeta},
    Error, Result,
};

/// Identity magic bytes (SOSV).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];

/// Vault version identifier.
pub const VERSION: u16 = 0;

/// Default public name for a vault.
pub const DEFAULT_VAULT_NAME: &str = "Login";

/// Mime type for vaults.
pub const MIME_TYPE_VAULT: &str = "application/sos+vault";

/// Authentication information.
#[derive(Debug, Default, Eq, PartialEq)]
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
    change_seq: u32,
    id: Uuid,
    name: String,
    #[serde(skip)]
    algorithm: Algorithm,
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            version: VERSION,
            change_seq: 0,
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
            change_seq: 0,
            algorithm,
            id,
            name,
        }
    }

    /// Get the version identifier.
    pub fn version(&self) -> &u16 {
        &self.version
    }

    /// Get the change sequence.
    pub fn change_seq(&self) -> &u32 {
        &self.change_seq
    }

    /// Set the change sequence.
    pub fn set_change_seq(&mut self, change_seq: u32) {
        self.change_seq = change_seq;
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Get the unique identifier.
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Get the public name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Encode for Summary {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_u16(self.version)?;
        ser.writer.write_u32(self.change_seq)?;
        self.algorithm.encode(&mut *ser)?;
        ser.writer.write_bytes(self.id.as_bytes())?;
        ser.writer.write_string(&self.name)?;
        Ok(())
    }
}

impl Decode for Summary {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.version = de.reader.read_u16()?;
        self.change_seq = de.reader.read_u32()?;
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
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    identity: FileIdentity,
    summary: Summary,
    meta: Option<AeadPack>,
    auth: Auth,
}

impl Header {
    /// Create a new header.
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
        Self {
            identity: FileIdentity(IDENTITY),
            summary: Summary::new(id, name, algorithm),
            meta: None,
            auth: Default::default(),
        }
    }

    /// Get the public name for this vault.
    pub fn name(&self) -> &str {
        &self.summary.name
    }

    /// Set the public name for this vault.
    pub fn set_name(&mut self, name: String) {
        self.summary.name = name;
    }

    /// Get the encrypted meta data for the vault.
    pub fn meta(&self) -> Option<&AeadPack> {
        self.meta.as_ref()
    }

    /// Set the encrypted meta data for the vault.
    pub fn set_meta(&mut self, meta: Option<AeadPack>) {
        self.meta = meta;
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
        FileIdentity::read_identity(&mut de, &IDENTITY)?;

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
    fn read_header_stream(stream: &mut impl ReadStream) -> Result<Header> {
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
            identity: FileIdentity(IDENTITY),
            summary: Default::default(),
            meta: None,
            auth: Default::default(),
        }
    }
}

impl Encode for Header {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.identity.encode(&mut *ser)?;

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
        self.identity.decode(&mut *de)?;

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
    data: HashMap<SecretId, (AeadPack, AeadPack)>,
}

impl Contents {
    /// Encode a single row into a serializer.
    pub fn encode_row(
        ser: &mut Serializer,
        key: &SecretId,
        row: &(AeadPack, AeadPack),
    ) -> BinaryResult<()> {
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        ser.writer.write_bytes(key.as_bytes())?;
        row.0.encode(&mut *ser)?;
        row.1.encode(&mut *ser)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub fn decode_row(
        de: &mut Deserializer,
    ) -> BinaryResult<(SecretId, (AeadPack, AeadPack))> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        let uuid: [u8; 16] =
            de.reader.read_bytes(16)?.as_slice().try_into()?;
        let uuid = Uuid::from_bytes(uuid);

        let mut meta: AeadPack = Default::default();
        meta.decode(&mut *de)?;
        let mut secret: AeadPack = Default::default();
        secret.decode(&mut *de)?;
        Ok((uuid, (meta, secret)))
    }
}

impl Encode for Contents {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_u32(self.data.len() as u32)?;
        for (key, row) in &self.data {
            Contents::encode_row(ser, key, row)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let length = de.reader.read_u32()?;
        for _ in 0..length {
            let (uuid, (meta, secret)) = Contents::decode_row(de)?;
            self.data.insert(uuid, (meta, secret));
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
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
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

    /// Iterator for the secret keys.
    pub fn keys<'a>(&'a self) -> impl Iterator<Item = &'a Uuid> {
        self.contents.data.keys()
    }

    /// Get the salt used for passphrase authentication.
    pub fn salt(&self) -> Option<&String> {
        self.header.auth.salt.as_ref()
    }

    /// The file extension for vault files.
    pub fn extension() -> &'static str {
        "vault"
    }

    /// Get the summary for this vault.
    pub fn summary(&self) -> &Summary {
        &self.header.summary
    }

    /// Get the unique identifier for this vault.
    pub fn id(&self) -> &Uuid {
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
            .map(|(k, v)| (k, &v.0))
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
}

impl VaultAccess for Vault {
    fn summary(&self) -> Result<Summary> {
        Ok(self.header.summary.clone())
    }

    fn change_seq(&self) -> Result<u32> {
        Ok(self.header.summary.change_seq)
    }

    fn save(&mut self, buffer: &[u8]) -> Result<Payload> {
        let vault = Vault::read_buffer(buffer)?;
        *self = vault;
        let change_seq = self.change_seq()?;
        Ok(Payload::UpdateVault(change_seq))
    }

    fn vault_name(&self) -> Result<(String, Payload)> {
        Ok((
            self.name().to_string(),
            Payload::GetVaultName(self.change_seq()?),
        ))
    }

    fn set_vault_name(&mut self, name: String) -> Result<Payload> {
        let change_seq = if let Some(next_change_seq) =
            self.header.summary.change_seq.checked_add(1)
        {
            self.header.summary.set_change_seq(next_change_seq);
            next_change_seq
        } else {
            return Err(Error::TooManyChanges);
        };

        self.set_name(name.clone());

        Ok(Payload::SetVaultName(change_seq, Cow::Owned(name)))
    }

    fn create(&mut self, secret: (AeadPack, AeadPack)) -> Result<Payload> {
        let id = Uuid::new_v4();
        let change_seq = if let Some(next_change_seq) =
            self.header.summary.change_seq.checked_add(1)
        {
            self.header.summary.set_change_seq(next_change_seq);
            next_change_seq
        } else {
            return Err(Error::TooManyChanges);
        };

        let value = self.contents.data.entry(id.clone()).or_insert(secret);
        Ok(Payload::CreateSecret(change_seq, id, Cow::Borrowed(value)))
    }

    fn read<'a>(
        &'a self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'a, (AeadPack, AeadPack)>>, Payload)> {
        let change_seq = self.change_seq()?;
        let result = self.contents.data.get(id).map(Cow::Borrowed);
        Ok((result, Payload::ReadSecret(change_seq, *id)))
    }

    fn update(
        &mut self,
        id: &SecretId,
        secret: (AeadPack, AeadPack),
    ) -> Result<Option<Payload>> {
        if let Some(value) = self.contents.data.get_mut(id) {
            let change_seq = if let Some(next_change_seq) =
                self.header.summary.change_seq.checked_add(1)
            {
                self.header.summary.set_change_seq(next_change_seq);
                next_change_seq
            } else {
                return Err(Error::TooManyChanges);
            };

            *value = secret;

            Ok(Some(Payload::UpdateSecret(
                change_seq,
                *id,
                Cow::Borrowed(value),
            )))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, id: &SecretId) -> Result<Option<Payload>> {
        let change_seq = if let Some(next_change_seq) =
            self.header.summary.change_seq.checked_add(1)
        {
            self.header.summary.set_change_seq(next_change_seq);
            next_change_seq
        } else {
            return Err(Error::TooManyChanges);
        };

        let entry = self.contents.data.remove(id);
        if entry.is_some() {
            Ok(Some(Payload::DeleteSecret(change_seq, *id)))
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
    use crate::crypto::secret_key::*;
    use crate::diceware::generate_passphrase;
    use crate::operations::Payload;
    use crate::secret::*;

    use crate::test_utils::*;

    use anyhow::Result;
    use serde_binary::binary_rw::{MemoryStream, ReadStream, WriteStream};

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
        let (encryption_key, _) = mock_encryption_key()?;
        let mut vault = mock_vault();

        // TODO: encode the salt into the header meta data

        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";

        let (secret_meta, secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note)?;

        let meta_aead = vault.encrypt(&encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(&encryption_key, &secret_bytes)?;

        let secret_id = match vault.create((meta_aead, secret_aead))? {
            Payload::CreateSecret(_, secret_id, _) => secret_id,
            _ => unreachable!(),
        };

        let mut stream = MemoryStream::new();
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
        assert_eq!(vault, decoded);

        let (row, _) = decoded.read(&secret_id)?;

        let value = row.unwrap();
        let (row_meta, row_secret) = value.as_ref();

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
        let _vault = Vault::read_file(
            "./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault",
        )?;
        Ok(())
    }

    #[test]
    fn decode_buffer() -> Result<()> {
        let buffer = std::fs::read(
            "./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault",
        )?;
        let _vault: Vault = decode(&buffer)?;
        Ok(())
    }
}
