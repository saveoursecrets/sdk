//! Helper that reads and writes the magic identity bytes for file formats.
use serde_binary::{Deserializer, Serializer};
use std::{fs::File, io::Read, path::Path};

use crate::{Error, Result};

/// Read and write the identity bytes for a file.
pub struct FileIdentity;

impl FileIdentity {
    /// Read the identity magic bytes from a file.
    pub fn read_file<P: AsRef<Path>>(path: P, identity: &[u8]) -> Result<()> {
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        if len >= identity.len() as u64 {
            let mut buffer = [0u8; 4];
            file.read_exact(&mut buffer)?;
            for (index, ident) in identity.iter().enumerate() {
                let byte = buffer[index];
                if byte != *ident {
                    return Err(Error::BadIdentity(byte));
                }
            }
        } else {
            return Err(Error::IdentityLength);
        }
        Ok(())
    }

    /// Read the identity magic bytes from a slice.
    pub fn read_slice(buffer: &[u8], identity: &[u8]) -> Result<()> {
        if buffer.len() >= identity.len() {
            for (index, ident) in identity.iter().enumerate() {
                let byte = buffer[index];
                if byte != *ident {
                    return Err(Error::BadIdentity(byte));
                }
            }
        } else {
            return Err(Error::IdentityLength);
        }
        Ok(())
    }

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

    /// Write the identity magic bytes.
    pub fn write_identity(
        ser: &mut Serializer,
        identity: &[u8],
    ) -> Result<()> {
        ser.writer.write_bytes(identity)?;
        Ok(())
    }
}
