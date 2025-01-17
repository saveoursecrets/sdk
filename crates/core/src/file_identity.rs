//! Helper functions to read and write the magic identity
//! bytes for file formats.
use crate::{Error, Result};
use binary_stream::futures::BinaryReader;
use tokio::io::{AsyncReadExt, AsyncSeek};

/// String of formatted identity bytes for error messages.
#[doc(hidden)]
pub fn format_identity_bytes(identity: &[u8]) -> String {
    let c =
        std::str::from_utf8(identity).expect("identity bytes to be UTF-8");
    format!("{:#04x?} ({})", identity, c)
    /*
    let c =
        std::str::from_utf8(identity).expect("identity bytes to be UTF-8");
    let mut s = String::new();
    for (index, byte) in identity.iter().enumerate() {
        s.push_str(&format!("{:#04x}", byte));
        if index < identity.len() - 1 {
            s.push_str(", ");
        }
    }
    s.push_str(&format!(" ({})", c));
    s
    */
}

/// Read identity bytes.
pub struct FileIdentity;

impl FileIdentity {
    /// Read the identity magic bytes from a slice.
    pub fn read_slice(buffer: &[u8], identity: &[u8]) -> Result<()> {
        if buffer.len() >= identity.len() {
            for (index, ident) in identity.iter().enumerate() {
                let byte = buffer[index];
                if byte != *ident {
                    return Err(Error::BadIdentity(
                        byte,
                        index,
                        format_identity_bytes(identity),
                    ));
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
        for (index, ident) in identity.iter().enumerate() {
            let byte = reader.read_u8().await?;
            if byte != *ident {
                return Err(Error::BadIdentity(
                    byte,
                    index,
                    format_identity_bytes(identity),
                ));
            }
        }
        Ok(())
    }
}
