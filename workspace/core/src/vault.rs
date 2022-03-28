//! Vault secret storage file format.
use binary_rw::{
    FileStream, OpenType,
    MemoryStream,
    Endian,
    BinaryReader, BinaryWriter, Stream,
};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::{
    crypto::{
        authorize::PublicKey,
        passphrase::{generate_salt, generate_secret_key},
        AeadPack,
    },
    traits::{Decode, Encode},
    Error, Result,
};

const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x03];
const VERSION: u16 = 0;

/// Authentication information.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Auth {
    salt: Option<String>,
    public_keys: Vec<PublicKey>,
}

impl Encode for Auth {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_u32(self.public_keys.len() as u32)?;
        for public_key in &self.public_keys {
            public_key.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for Auth {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let length = reader.read_u32()?;
        for _ in 0..length {
            let mut public_key: PublicKey = Default::default();
            public_key.decode(reader)?;
            self.public_keys.push(public_key);
        }
        Ok(())
    }
}

/// File header, identifier and version information
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    identity: Box<[u8; 4]>,
    version: u16,
    id: Uuid,
    auth: Auth,
}

impl Header {
    /// Create a new header.
    pub fn new(id: Uuid) -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            id,
            auth: Default::default(),
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            id: Uuid::new_v4(),
            auth: Default::default(),
        }
    }
}

impl Encode for Header {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_bytes(self.identity.to_vec())?;
        writer.write_u16(self.version)?;
        writer.write_string(self.id.to_string())?;
        self.auth.encode(writer)?;
        Ok(())
    }
}

impl Decode for Header {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        for ident in &IDENTITY {
            let byte = reader.read_u8()?;
            if byte != *ident {
                return Err(Error::BadIdentity(byte));
            }
        }
        self.version = reader.read_u16()?;
        self.id = Uuid::parse_str(&reader.read_string()?)?;
        self.auth.decode(reader)?;
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
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_bool(self.meta.is_some())?;
        if let Some(meta) = &self.meta {
            meta.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for Index {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let has_meta = reader.read_bool()?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(reader)?;
            }
        }
        Ok(())
    }
}

/// The vault contents
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Contents {
    data: HashMap<Uuid, AeadPack>,
}

impl Encode for Contents {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_u32(self.data.len() as u32)?;
        for (key, item) in &self.data {
            writer.write_string(key.to_string())?;
            item.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let length = reader.read_u32()?;
        for _ in 0..length {
            let key = reader.read_string()?;
            let mut value: AeadPack = Default::default();
            value.decode(reader)?;
            self.data.insert(Uuid::parse_str(&key)?, value);
        }
        Ok(())
    }
}

/// Trailer including checksum
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Trailer {}

impl Encode for Trailer {
    fn encode(&self, _writer: &mut BinaryWriter) -> Result<()> {
        Ok(())
    }
}

impl Decode for Trailer {
    fn decode(&mut self, _reader: &mut BinaryReader) -> Result<()> {
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
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        self.header.encode(writer)?;
        self.index.encode(writer)?;
        self.contents.encode(writer)?;
        self.trailer.encode(writer)?;
        Ok(())
    }
}

impl Decode for Vault {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.header.decode(reader)?;
        //self.index.decode(reader)?;
        //self.contents.decode(reader)?;
        //self.trailer.decode(reader)?;
        Ok(())
    }
}

impl Vault {
    /// Create a new vault.
    pub fn new(id: Uuid) -> Self {
        Self {
            header: Header::new(id),
            index: Default::default(),
            contents: Default::default(),
            trailer: Default::default(),
        }
    }

    /// Initialize the vault with the given label and password.
    pub fn initialize<S: AsRef<str>>(&mut self, password: S) -> Result<[u8; 32]> {
        if self.header.auth.salt.is_none() {
            let salt = generate_salt();
            let private_key = generate_secret_key(password, &salt)?;

            // Store the salt so we can generate the same
            // private key later
            self.header.auth.salt = Some(salt.to_string());

            Ok(private_key)
        } else {
            Err(Error::VaultAlreadyInit)
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
    pub fn add_secret(&mut self, uuid: Uuid, secret: AeadPack) {
        self.contents.data.insert(uuid, secret);
    }

    /// Get an encrypted secret from the vault.
    pub fn get_secret(&self, uuid: &Uuid) -> Option<&AeadPack> {
        self.contents.data.get(uuid)
    }

    /// Encode a vault to binary.
    pub fn encode<'a>(stream: &'a mut impl Stream, vault: &Vault) -> Result<()> {
        let mut writer = BinaryWriter::new(stream, Endian::Big);
        vault.encode(&mut writer)?;
        Ok(())
    }

    /// Decode a vault from binary.
    pub fn decode(stream: &mut impl Stream) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        let mut reader = BinaryReader::new(stream, Endian::Big);
        vault.decode(&mut reader)?;
        Ok(vault)
    }

    /// Read a vault from a buffer.
    pub fn read_buffer<B: AsRef<[u8]>>(buffer: B) -> Result<Vault> {
        let vault: Vault = from_encoded_buffer(buffer.as_ref().to_vec())?;
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
    pub fn get_public_key(&mut self, public_key: &PublicKey) -> Option<(usize, &PublicKey)> {
        self.header
            .auth
            .public_keys
            .iter()
            .enumerate()
            .find_map(|(i, k)| if k == public_key { Some((i, k)) } else { None })
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
pub fn into_encoded_buffer(encodable: &impl Encode) -> Result<Vec<u8>> {
    let mut stream = MemoryStream::new();
    let mut writer = BinaryWriter::new(&mut stream, Endian::Big);
    encodable.encode(&mut writer)?;
    Ok(stream.into())
}

/// Decode into a binary buffer.
pub fn from_encoded_buffer<T: Decode + Default>(buffer: Vec<u8>) -> Result<T> {
    let mut stream: MemoryStream = buffer.into();
    let mut reader = BinaryReader::new(&mut stream, Endian::Big);
    let mut decoded: T = T::default();
    decoded.decode(&mut reader)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use binary_rw::{MemoryStream, Stream};
    use uuid::Uuid;

    #[test]
    fn encode_decode_empty_vault() -> Result<()> {
        let uuid = Uuid::new_v4();
        let vault = Vault::new(uuid);
        let mut stream = MemoryStream::new();
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
        assert_eq!(vault, decoded);
        Ok(())
    }

    // FIXME: move test files to fixtures directory

    /*
    #[test]
    fn decode_file() -> Result<()> {
        let vault = Vault::read_file("../../vaults/0x8a67d6f4aae8165512774d63992623e10494c69f/b9c748d1-223a-4b2c-8bdb-6dbd03be5629.vault")?;
        println!("Vault {:#?}", vault);
        Ok(())
    }

    #[test]
    fn decode_buffer() -> Result<()> {
        let buffer = std::fs::read("../../vaults/0x8a67d6f4aae8165512774d63992623e10494c69f/b9c748d1-223a-4b2c-8bdb-6dbd03be5629.vault")?;

        println!("{}", hex::encode(&buffer));

        let vault: Vault = from_encoded_buffer(buffer)?;
        println!("Vault {:#?}", vault);
        Ok(())
    }
    */
}
