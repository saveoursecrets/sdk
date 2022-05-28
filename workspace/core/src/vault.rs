//! Vault secret storage file format.
use serde::{Deserialize, Serialize};
use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, Stream,
    },
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};
use std::{borrow::Cow, collections::HashMap, path::Path};
use uuid::Uuid;

use crate::{
    crypto::{
        aesgcm256, algorithms::*, authorize::PublicKey, secret_key::SecretKey,
        xchacha20poly1305, AeadPack,
    },
    file_identity::FileIdentity,
    operations::{Payload, VaultAccess},
    secret::VaultMeta,
    Error, Result,
};

/// Identity magic bytes (SOSV).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];

/// Vault version identifier.
pub const VERSION: u16 = 0;

/// Default public name for a vault.
pub const DEFAULT_VAULT_NAME: &str = "Login";

/// Authentication information.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Auth {
    salt: Option<String>,
    public_keys: Vec<PublicKey>,
}

impl Encode for Auth {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.salt.serialize(&mut *ser)?;
        self.public_keys.serialize(&mut *ser)?;
        Ok(())
    }
}

impl Decode for Auth {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.salt = Deserialize::deserialize(&mut *de)?;
        self.public_keys = Deserialize::deserialize(&mut *de)?;
        Ok(())
    }
}

/// Summary holding basic file information such as version,
/// unique identifier and name.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Summary {
    version: u16,
    id: Uuid,
    name: String,
    #[serde(skip)]
    algorithm: Algorithm,
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
            id,
            name,
            algorithm,
            version: VERSION,
        }
    }

    /// Get the version identifier.
    pub fn version(&self) -> &u16 {
        &self.version
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

        let uuid: [u8; 16] = de.reader.read_bytes(16)?.as_slice().try_into()?;
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

    /// Get the encrypted meta data for the vault.
    pub fn meta(&self) -> Option<&AeadPack> {
        self.meta.as_ref()
    }

    /// Set the encrypted meta data for the vault.
    pub fn set_meta(&mut self, meta: Option<AeadPack>) {
        self.meta = meta;
    }

    /*
    /// Read the identity magic bytes.
    fn read_identity(de: &mut Deserializer, identity: &[u8]) -> Result<()> {
        for ident in identity {
            let byte = de.reader.read_u8()?;
            if byte != *ident {
                return Err(Error::BadIdentity(byte));
            }
        }
        Ok(())
    }
    */

    /// Read the summary for a vault from a file.
    pub fn read_summary<P: AsRef<Path>>(file: P) -> Result<Summary> {
        let mut stream = FileStream::new(file.as_ref(), OpenType::Open)?;
        let reader = BinaryReader::new(&mut stream, Endian::Big);
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
    sequence_num: u32,
    data: HashMap<Uuid, (AeadPack, AeadPack)>,
}

impl Contents {
    /// Encode a single row into a serializer.
    pub fn encode_row(
        ser: &mut Serializer,
        key: &Uuid,
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
    ) -> BinaryResult<(Uuid, (AeadPack, AeadPack))> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        let uuid: [u8; 16] = de.reader.read_bytes(16)?.as_slice().try_into()?;
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
        ser.writer.write_u32(self.sequence_num)?;
        ser.writer.write_u32(self.data.len() as u32)?;
        for (key, row) in &self.data {
            Contents::encode_row(ser, key, row)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.sequence_num = de.reader.read_u32()?;
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
    pub fn decrypt(&self, key: &SecretKey, aead: &AeadPack) -> Result<Vec<u8>> {
        match self.algorithm() {
            Algorithm::XChaCha20Poly1305(_) => {
                xchacha20poly1305::decrypt(key, aead)
            }
            Algorithm::AesGcm256(_) => aesgcm256::decrypt(key, aead),
        }
    }

    /// Get the salt used for passphrase authentication.
    pub fn salt(&self) -> Option<&String> {
        self.header.auth.salt.as_ref()
    }

    /// The file extension for vault files.
    pub fn extension() -> &'static str {
        "vault"
    }

    /// Get the unique identifier for this vault.
    pub fn id(&self) -> &Uuid {
        &self.header.summary.id
    }

    /// Get the public name for this vault.
    pub fn name(&self) -> &str {
        &self.header.summary.name
    }

    /// Set the public name for this vault.
    pub fn set_name(&mut self, name: String) {
        self.header.summary.name = name;
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
    pub fn encode(stream: &mut impl Stream, vault: &Vault) -> Result<()> {
        let writer = BinaryWriter::new(stream, Endian::Big);
        let mut serializer = Serializer { writer };
        vault.encode(&mut serializer)?;
        Ok(())
    }

    /// Decode a vault from binary.
    pub fn decode(stream: &mut impl Stream) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        let reader = BinaryReader::new(stream, Endian::Big);
        let mut deserializer = Deserializer { reader };
        vault.decode(&mut deserializer)?;
        Ok(vault)
    }

    /// Read a vault from a buffer.
    pub fn read_buffer<B: AsRef<[u8]>>(buffer: B) -> Result<Vault> {
        let vault: Vault = decode(buffer.as_ref().to_vec())?;
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

    /// Get the list of public keys.
    pub fn public_keys(&self) -> &Vec<PublicKey> {
        &self.header.auth.public_keys
    }

    /// Check if a public key already exists.
    pub fn get_public_key(
        &mut self,
        public_key: &PublicKey,
    ) -> Option<(usize, &PublicKey)> {
        self.header
            .auth
            .public_keys
            .iter()
            .enumerate()
            .find_map(
                |(i, k)| if k == public_key { Some((i, k)) } else { None },
            )
    }

    /// Add a public key to this vault.
    pub fn add_public_key(&mut self, public_key: PublicKey) {
        self.header.auth.public_keys.push(public_key)
    }

    /// Remove a public key from this vault.
    pub fn remove_public_key(&mut self, public_key: &PublicKey) -> bool {
        if let Some((index, _)) = self.get_public_key(public_key) {
            self.header.auth.public_keys.remove(index);
            true
        } else {
            false
        }
    }
}

impl VaultAccess for Vault {
    fn create(
        &mut self,
        uuid: Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Payload> {
        let id = uuid;
        let value = self.contents.data.entry(uuid).or_insert(secret);
        Ok(Payload::CreateSecret(id, Cow::Borrowed(value)))
    }

    fn read<'a>(
        &'a self,
        uuid: &Uuid,
    ) -> Result<(Option<Cow<'a, (AeadPack, AeadPack)>>, Payload)> {
        let id = *uuid;
        let result = self.contents.data.get(uuid).map(Cow::Borrowed);
        Ok((result, Payload::ReadSecret(id)))
    }

    fn update(
        &mut self,
        uuid: &Uuid,
        secret: (AeadPack, AeadPack),
    ) -> Result<Option<Payload>> {
        let id = *uuid;
        if let Some(value) = self.contents.data.get_mut(uuid) {
            *value = secret;
            Ok(Some(Payload::UpdateSecret(id, Cow::Borrowed(value))))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, uuid: &Uuid) -> Result<Payload> {
        let id = *uuid;
        self.contents.data.remove(uuid);
        Ok(Payload::DeleteSecret(id))
    }
}

/// Encode into a binary buffer.
pub fn encode(encodable: &impl Encode) -> Result<Vec<u8>> {
    Ok(serde_binary::encode(encodable, Endian::Big)?)
}

/// Decode into a binary buffer.
pub fn decode<T: Decode + Default>(buffer: Vec<u8>) -> Result<T> {
    Ok(serde_binary::decode::<T>(buffer, Endian::Big)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret_key::*;
    use crate::diceware::generate_passphrase;
    use crate::secret::*;

    use crate::test_utils::*;

    use anyhow::Result;
    use serde_binary::binary_rw::{MemoryStream, Stream};
    use uuid::Uuid;

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

        let (secret_id, secret_meta, secret_value, meta_bytes, secret_bytes) =
            mock_secret_note(secret_label, secret_note)?;

        let meta_aead = vault.encrypt(&encryption_key, &meta_bytes)?;
        let secret_aead = vault.encrypt(&encryption_key, &secret_bytes)?;

        let _ = vault.create(secret_id, (meta_aead, secret_aead));

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

        let row_meta: SecretMeta = decode(row_meta)?;
        let row_secret: Secret = decode(row_secret)?;

        assert_eq!(secret_meta, row_meta);
        assert_eq!(secret_value, row_secret);

        match &row_secret {
            Secret::Text(value) => {
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
        let _vault: Vault = decode(buffer)?;
        Ok(())
    }
}
