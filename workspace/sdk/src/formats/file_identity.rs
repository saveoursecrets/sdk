//! Helper that reads and writes the magic identity bytes for file formats.
use binary_stream::tokio::{BinaryReader, BinaryWriter};
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncSeek, AsyncWriteExt};

use crate::{vfs::File, Error, Result};

/// Read and write the identity bytes for a file.
pub struct FileIdentity;

impl FileIdentity {
    /// Read the identity magic bytes from a file.
    pub async fn read_file<P: AsRef<Path>>(
        path: P,
        identity: &[u8],
    ) -> Result<File> {
        let mut file = File::open(path.as_ref()).await?;
        let len = file.metadata().await?.len();
        if len >= identity.len() as u64 {
            let mut buffer = [0u8; 4];
            file.read_exact(&mut buffer).await?;
            for (index, ident) in identity.iter().enumerate() {
                let byte = buffer[index];
                if byte != *ident {
                    return Err(Error::BadIdentity(byte));
                }
            }
        } else {
            return Err(Error::IdentityLength);
        }
        Ok(file)
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
    pub async fn read_identity<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
        identity: &[u8],
    ) -> Result<()> {
        for ident in identity {
            let byte = reader.read_u8().await?;
            if byte != *ident {
                return Err(Error::BadIdentity(byte));
            }
        }
        Ok(())
    }

    /// Write the identity magic bytes.
    pub async fn write_identity<
        W: AsyncWriteExt + AsyncSeek + Unpin + Send,
    >(
        writer: &mut BinaryWriter<W>,
        identity: &[u8],
    ) -> Result<()> {
        writer.write_bytes(identity).await?;
        Ok(())
    }
}
