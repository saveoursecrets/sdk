//! Type that represents the magic identity bytes for file formats.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};

use crate::{Error, Result};

/// Aduit log identity magic bytes (SOSA).
pub const AUDIT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

/// Write-ahead log identity magic bytes (SOSW).
pub const WAL_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

/// Patch file identity magic bytes (SOSP).
pub const PATCH_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x50];

/// Vault file identity magic bytes (SOSV).
pub const VAULT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];

/// Read and write the identity bytes for a file.
#[derive(Debug, Eq, PartialEq)]
pub struct FileIdentity(pub [u8; 4]);

impl FileIdentity {
    /// Read the identity magic bytes.
    pub fn read_identity(
        de: &mut Deserializer,
        identity: &[u8],
    ) -> Result<()> {
        for ident in identity {
            let byte = de.reader.read_u8()?;
            if byte != *ident {
                return Err(Error::BadIdentity(byte));
            }
        }
        Ok(())
    }
}

impl Encode for FileIdentity {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&self.0)?;
        Ok(())
    }
}

impl Decode for FileIdentity {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        FileIdentity::read_identity(de, &self.0)
            .map_err(|e| BinaryError::Boxed(Box::from(e)))?;
        Ok(())
    }
}
