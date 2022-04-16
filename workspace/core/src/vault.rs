//! Vault secret storage file format.
use serde::{Deserialize, Serialize};
use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, Stream,
    },
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::{
    crypto::{
        aesgcm256, algorithms::*, authorize::PublicKey, secret_key::SecretKey,
        xchacha20poly1305, AeadPack,
    },
    secret::VaultMeta,
    Error, Result,
};

const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x33];
const VERSION: u16 = 0;

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

/// File header, identifier and version information
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    identity: Box<[u8; 4]>,
    version: u16,
    algorithm: Algorithm,
    id: Uuid,
    name: String,
    auth: Auth,
}

impl Header {
    /// Create a new header.
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            algorithm,
            id,
            name,
            auth: Default::default(),
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            algorithm: Default::default(),
            id: Uuid::new_v4(),
            name: DEFAULT_VAULT_NAME.to_string(),
            auth: Default::default(),
        }
    }
}

impl Encode for Header {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(self.identity.to_vec())?;
        ser.writer.write_u16(self.version)?;
        self.algorithm.encode(&mut *ser)?;
        ser.writer.write_string(self.id.to_string())?;
        ser.writer.write_string(&self.name)?;
        self.auth.encode(&mut *ser)?;
        Ok(())
    }
}

impl Decode for Header {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        for ident in &IDENTITY {
            let byte = de.reader.read_u8()?;
            if byte != *ident {
                return Err(BinaryError::Boxed(Box::from(Error::BadIdentity(
                    byte,
                ))));
            }
        }
        self.version = de.reader.read_u16()?;
        self.algorithm.decode(&mut *de)?;

        if ALGORITHMS
            .iter()
            .find(|a| *a == self.algorithm.as_ref())
            .is_none()
        {
            return Err(BinaryError::Boxed(Box::from(
                Error::UnknownAlgorithm(self.algorithm.into()),
            )));
        }

        self.id =
            Uuid::parse_str(&de.reader.read_string()?).map_err(Box::from)?;
        self.name = de.reader.read_string()?;
        self.auth.decode(&mut *de)?;
        Ok(())
    }
}

/// Index of meta data describing the contents.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Index {
    meta: Option<AeadPack>,
}

impl Index {
    /// Get the encrypted meta data for the index.
    pub fn meta(&self) -> Option<&AeadPack> {
        self.meta.as_ref()
    }

    /// Set the encrypted meta data for the index.
    pub fn set_meta(&mut self, meta: Option<AeadPack>) {
        self.meta = meta;
    }
}

impl Encode for Index {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bool(self.meta.is_some())?;
        if let Some(meta) = &self.meta {
            meta.encode(ser)?;
        }
        Ok(())
    }
}

impl Decode for Index {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let has_meta = de.reader.read_bool()?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(de)?;
            }
        }

        Ok(())
    }
}

/// The vault contents
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Contents {
    data: HashMap<Uuid, (AeadPack, AeadPack)>,
}

impl Encode for Contents {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_u32(self.data.len() as u32)?;
        for (key, item) in &self.data {
            key.serialize(&mut *ser)?;
            item.0.encode(&mut *ser)?;
            item.1.encode(&mut *ser)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let length = de.reader.read_u32()?;
        for _ in 0..length {
            let key: Uuid = Deserialize::deserialize(&mut *de)?;
            let mut meta: AeadPack = Default::default();
            meta.decode(&mut *de)?;
            let mut secret: AeadPack = Default::default();
            secret.decode(&mut *de)?;
            self.data.insert(key, (meta, secret));
        }
        Ok(())
    }
}

/// Trailer including checksum
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Trailer {}

impl Encode for Trailer {
    fn encode(&self, _ser: &mut Serializer) -> BinaryResult<()> {
        Ok(())
    }
}

impl Decode for Trailer {
    fn decode(&mut self, _de: &mut Deserializer) -> BinaryResult<()> {
        Ok(())
    }
}

/// Vault file storage.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Vault {
    header: Header,
    index: Index,
    contents: Contents,
    trailer: Trailer,
}

impl Encode for Vault {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        self.header.encode(ser)?;
        self.index.encode(ser)?;
        self.contents.encode(ser)?;
        self.trailer.encode(ser)?;
        Ok(())
    }
}

impl Decode for Vault {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        self.header.decode(de)?;
        self.index.decode(de)?;
        self.contents.decode(de)?;
        self.trailer.decode(de)?;
        Ok(())
    }
}

impl Vault {
    /// Create a new vault.
    pub fn new(id: Uuid, name: String, algorithm: Algorithm) -> Self {
        Self {
            header: Header::new(id, name, algorithm),
            index: Default::default(),
            contents: Default::default(),
            trailer: Default::default(),
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

            self.index = Default::default();
            let default_meta: VaultMeta = Default::default();
            let meta_aead =
                self.encrypt(&private_key, &encode(&default_meta)?)?;
            self.index.set_meta(Some(meta_aead));
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

    /// The file extensions for vaults.
    pub fn extension() -> &'static str {
        "vault"
    }

    /// Get the unique identifier for this vault.
    pub fn id(&self) -> &Uuid {
        &self.header.id
    }

    /// Get the public name for this vault.
    pub fn name(&self) -> &str {
        &self.header.name
    }

    /// Set the public name for this vault.
    pub fn set_name(&mut self, name: String) {
        self.header.name = name;
    }

    /// Get the encryption algorithm for the vault.
    pub fn algorithm(&self) -> &Algorithm {
        &self.header.algorithm
    }

    /// Get the meta data index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Get the mutable meta data index.
    pub fn index_mut(&mut self) -> &mut Index {
        &mut self.index
    }

    /// Set the vault meta data index.
    pub fn set_index(&mut self, index: Index) {
        self.index = index;
    }

    /// Add an encrypted secret to the vault.
    pub fn add_secret(&mut self, uuid: Uuid, secret: (AeadPack, AeadPack)) {
        self.contents.data.insert(uuid, secret);
    }

    /// Remove an encrypted secret from the vault.
    pub fn remove_secret(&mut self, uuid: &Uuid) {
        self.contents.data.remove(uuid);
    }

    /// Get an encrypted secret from the vault.
    pub fn get_secret(&self, uuid: &Uuid) -> Option<&(AeadPack, AeadPack)> {
        self.contents.data.get(uuid)
    }

    /// Get the meta data for all the secrets.
    pub fn meta_data(&self) -> HashMap<&Uuid, &AeadPack> {
        self.contents.data.iter()
            .map(|(k, v)| (k, &v.0)).collect::<HashMap<_, _>>()
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
    use anyhow::Result;
    use serde_binary::binary_rw::{MemoryStream, Stream};
    use uuid::Uuid;

    #[test]
    fn encode_decode_empty_vault() -> Result<()> {
        let uuid = Uuid::new_v4();
        let vault = Vault::new(
            uuid,
            String::from(DEFAULT_VAULT_NAME),
            Default::default(),
        );
        let mut stream = MemoryStream::new();
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
        assert_eq!(vault, decoded);
        Ok(())
    }

    #[test]
    fn decode_file() -> Result<()> {
        let vault = Vault::read_file(
            "./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault",
        )?;
        Ok(())
    }

    #[test]
    fn decode_buffer() -> Result<()> {
        let buffer = std::fs::read(
            "./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault",
        )?;
        let vault: Vault = decode(buffer)?;
        Ok(())
    }
}
