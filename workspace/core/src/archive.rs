//! Read and write archives of vaults.

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
};
use tar::{Builder, EntryType, Header};
use time::OffsetDateTime;

use crate::{constants::VAULT_EXT, vault::VaultId, Result};

/// Manifest used to determine if the archive is supported
/// for import purposes.
#[derive(Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Address of the identity file.
    pub address: String,

    /// Checksum of the identity vault.
    pub identity: String,

    /// Map of vault identifiers to checksums.
    pub vaults: HashMap<VaultId, String>,
}

/// Writer to generate the archive.
///
/// Creating archives assumes the vault buffers have already been
/// verified to be valid vaults.
pub struct Writer<W: Write> {
    builder: Builder<W>,
    manifest: Manifest,
}

impl<W: Write> Writer<W> {
    /// Create a new writer.
    pub fn new(inner: W) -> Self {
        Self {
            builder: Builder::new(inner),
            manifest: Default::default(),
        }
    }

    fn finish_header(&self, header: &mut Header) {
        let now = OffsetDateTime::now_utc();
        header.set_entry_type(EntryType::Regular);
        header.set_mtime(now.unix_timestamp() as u64);
        header.set_mode(0o755);
        header.set_cksum();
    }

    /// Set the identity vault for the archive.
    pub fn set_identity(
        &mut self,
        address: String,
        vault: &[u8],
    ) -> Result<()> {
        let mut path = PathBuf::from(&address);
        path.set_extension(VAULT_EXT);

        self.manifest.address = address;
        self.manifest.identity =
            hex::encode(Keccak256::digest(vault).as_slice());

        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(vault.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, vault)?;

        Ok(())
    }

    /// Add a vault to the archive.
    pub fn add_vault(
        &mut self,
        vault_id: VaultId,
        vault: &[u8],
    ) -> Result<()> {
        let mut path = PathBuf::from(vault_id.to_string());
        path.set_extension(VAULT_EXT);

        let checksum = hex::encode(Keccak256::digest(vault).as_slice());

        self.manifest.vaults.insert(vault_id, checksum);

        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(vault.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, vault)?;

        Ok(())
    }

    /// Add the manifest and finish building the tarball.
    pub fn finish(mut self) -> Result<W> {
        let manifest = serde_json::to_vec_pretty(&self.manifest)?;

        let path = PathBuf::from("sos-manifest.json");
        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(manifest.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, manifest.as_slice())?;

        Ok(self.builder.into_inner()?)
    }
}

/// Compress a tarball with gzip compression.
pub fn compress_with_filename<R, W>(
    file_name: &str,
    mut reader: R,
    writer: W,
) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut gz = GzBuilder::new()
        .filename(file_name)
        .write(writer, Compression::default());
    std::io::copy(&mut reader, &mut gz)?;
    gz.finish()?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{encode, identity::Identity, vault::Vault};
    use anyhow::Result;
    use secrecy::SecretString;

    #[test]
    fn archive_buffer() -> Result<()> {
        let mut archive = Vec::new();
        let mut writer = Writer::new(&mut archive);

        let (address, identity_vault) = Identity::new_login_vault(
            "Mock".to_string(),
            SecretString::new("mock-password".to_string()),
        )?;

        let identity = encode(&identity_vault)?;
        writer.set_identity(address, &identity)?;

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        writer.add_vault(*vault.id(), &vault_buffer)?;

        let tarball = writer.finish()?;

        let mut tar_gz = Vec::new();
        compress_with_filename("mock.tar", tarball.as_slice(), &mut tar_gz)?;

        Ok(())
    }
}
