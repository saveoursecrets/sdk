//! Vault secret storage file format.
use anyhow::{bail, Result};
use binary_rw::{
    filestream::{Filestream, OpenType},
    BinaryReader, BinaryWriter, Stream,
};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::{
    crypto::{authorize::PublicKey, AeadPack},
    traits::{Decode, Encode},
};

const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x03];
const VERSION: u16 = 0;

/// File header, identifier and version information
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    identity: Box<[u8; 4]>,
    version: u16,
    id: Uuid,
    public_keys: Vec<PublicKey>,
}

impl Header {
    /// Create a new header.
    pub fn new(id: Uuid) -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            id,
            public_keys: Default::default(),
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            identity: Box::new(IDENTITY),
            version: VERSION,
            id: Uuid::new_v4(),
            public_keys: Default::default(),
        }
    }
}

impl Encode for Header {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_bytes(self.identity.to_vec())?;
        writer.write_u16(self.version)?;
        writer.write_string(self.id.to_string())?;
        writer.write_usize(self.public_keys.len())?;
        for public_key in &self.public_keys {
            public_key.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for Header {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        for ident in &IDENTITY {
            let byte = reader.read_u8()?;
            if byte != *ident {
                bail!("bad identity byte {:x}", byte);
            }
        }
        self.version = reader.read_u16()?;
        self.id = Uuid::parse_str(&reader.read_string()?)?;
        let length = reader.read_usize()?;
        for _ in 0..length {
            let mut public_key: PublicKey = Default::default();
            public_key.decode(reader)?;
            self.public_keys.push(public_key);
        }
        Ok(())
    }
}

/// Index of meta data describing the contents.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Index {
    meta: AeadPack,
}

impl Encode for Index {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        self.meta.encode(writer)?;
        Ok(())
    }
}

impl Decode for Index {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.meta.decode(reader)?;
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
        writer.write_usize(self.data.len())?;
        for (key, item) in &self.data {
            writer.write_string(key.to_string())?;
            item.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for Contents {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let length = reader.read_usize()?;
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
        self.index.decode(reader)?;
        self.contents.decode(reader)?;
        self.trailer.decode(reader)?;
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

    /// The file extensions for vaults.
    pub fn extension() -> &'static str {
        "vault"
    }

    /// Get the unique identifier for this vault.
    pub fn id(&self) -> &Uuid {
        &self.header.id
    }

    /// Get the vault meta data index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Set the vault meta data index.
    pub fn set_index(&mut self, index: Index) {
        self.index = index;
    }

    /// Encode a vault to binary.
    pub fn encode<'a>(stream: &'a mut impl Stream, vault: &Vault) -> Result<()> {
        let mut writer = BinaryWriter::new(stream);
        vault.encode(&mut writer)?;
        Ok(())
    }

    /// Decode a vault from binary.
    pub fn decode(stream: &mut impl Stream) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        let mut reader = BinaryReader::new(stream);
        vault.decode(&mut reader)?;
        Ok(vault)
    }

    /// Read a vault from a file.
    pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vault> {
        let mut stream = Filestream::new(path, OpenType::Open)?;
        Vault::decode(&mut stream)
    }

    /// Write this vault to a file.
    pub fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut stream = Filestream::new(path, OpenType::OpenAndCreate)?;
        Vault::encode(&mut stream, self)
    }

    /// Get the list of public keys.
    pub fn public_keys(&self) -> &Vec<PublicKey> {
        &self.header.public_keys
    }

    /// Check if a public key already exists.
    pub fn get_public_key(&mut self, public_key: &PublicKey) -> Option<(usize, &PublicKey)> {
        self.header
            .public_keys
            .iter()
            .enumerate()
            .find_map(|(i, k)| if k == public_key { Some((i, k)) } else { None })
    }

    /// Add a public key to this vault.
    pub fn add_public_key(&mut self, public_key: PublicKey) {
        self.header.public_keys.push(public_key)
    }

    /// Remove a public key from this vault.
    pub fn remove_public_key(&mut self, public_key: &PublicKey) -> bool {
        if let Some((index, _)) = self.get_public_key(public_key) {
            self.header.public_keys.remove(index);
            true
        } else {
            false
        }
    }
}

/// Encode into a binary buffer.
pub fn into_encoded_buffer(encodable: &impl Encode) -> Result<Vec<u8>> {
    use binary_rw::memorystream::Memorystream;
    let mut stream = Memorystream::new()?;
    let mut writer = BinaryWriter::new(&mut stream);
    encodable.encode(&mut writer)?;
    Ok(stream.into())
}

/// Decode into a binary buffer.
pub fn from_encoded_buffer<T: Decode + Default>(buffer: Vec<u8>) -> Result<T> {
    use binary_rw::memorystream::Memorystream;
    let mut stream: Memorystream = buffer.into();
    let mut reader = BinaryReader::new(&mut stream);
    let mut decoded: T = T::default();
    decoded.decode(&mut reader)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::Vault;
    use anyhow::Result;
    use binary_rw::{memorystream::Memorystream, Stream};
    use uuid::Uuid;

    #[test]
    fn encode_decode_empty_vault() -> Result<()> {
        let uuid = Uuid::new_v4();
        let vault = Vault::new(uuid);
        let mut stream = Memorystream::new()?;
        Vault::encode(&mut stream, &vault)?;

        stream.seek(0)?;
        let decoded = Vault::decode(&mut stream)?;
        assert_eq!(vault, decoded);
        Ok(())
    }
}
