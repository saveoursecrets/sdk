//! Helper that reads and writes the magic identity bytes for file formats.
use crate::{Error, Result};
use sos_vfs::File;
use std::path::Path;

/// Read the identity magic bytes from a file.
pub async fn read_file_identity_bytes<P: AsRef<Path>>(
    path: P,
    identity: &[u8],
) -> Result<File> {
    use tokio::io::AsyncReadExt;
    let mut file = File::open(path.as_ref()).await?;
    let len = file.metadata().await?.len();
    if len >= identity.len() as u64 {
        let mut buffer = [0u8; 4];
        file.read_exact(&mut buffer).await?;
        for (index, ident) in identity.iter().enumerate() {
            let byte = buffer[index];
            if byte != *ident {
                return Err(Error::BadIdentity(
                    byte,
                    index,
                    sos_core::file_identity::format_identity_bytes(identity),
                ));
            }
        }
    } else {
        return Err(Error::IdentityLength);
    }
    Ok(file)
}
