//! Read and write archives of vaults.
//!
//! Designed to avoid file system operations so it can
//! also be used from webassembly.

use flate2::{
    write::{GzDecoder, GzEncoder},
    Compression,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, Write},
    path::PathBuf,
};
use tar::{Archive, Builder, Entry, EntryType, Header};
use time::OffsetDateTime;

use crate::{
    constants::{ARCHIVE_MANIFEST, VAULT_EXT},
    vault::VaultId,
    Error, Result,
};

/// Manifest used to determine if the archive is supported
/// for import purposes.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Address of the identity file.
    pub address: String,

    /// Checksum of the identity vault.
    pub identity: String,

    /// Map of vault identifiers to checksums.
    pub vaults: HashMap<VaultId, String>,
}

/// Write to an archive.
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

        let path = PathBuf::from(ARCHIVE_MANIFEST);
        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(manifest.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, manifest.as_slice())?;

        Ok(self.builder.into_inner()?)
    }
}

/// Compress to a gzip stream.
pub fn deflate<R, W>(mut reader: R, writer: W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut encoder = GzEncoder::new(writer, Compression::default());
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    Ok(())
}

/// Decompress a gzip stream.
pub fn inflate<R, W>(mut reader: R, writer: W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut decoder = GzDecoder::new(writer);
    std::io::copy(&mut reader, &mut decoder)?;
    decoder.finish()?;
    Ok(())
}

fn read_entry_data<R>(entry: &mut Entry<R>) -> Result<Vec<u8>>
where
    R: Read,
{
    let size = entry.size();
    let mut buffer = Vec::with_capacity(size as usize);
    entry.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Read from an archive.
pub struct Reader<R: Read + Seek> {
    archive: Archive<R>,
    //manifest: Option<Manifest>,
    entries: HashMap<PathBuf, Vec<u8>>,
}

impl<R: Read + Seek> Reader<R> {
    /// Create a new reader.
    pub fn new(inner: R) -> Self {
        Self {
            archive: Archive::new(inner),
            entries: Default::default(),
        }
    }

    /// Prepare the archive for reading by parsing the manifest file.
    pub fn prepare(&mut self) -> Result<Manifest> {
        let mut manifest: Option<Manifest> = None;
        let it = self.archive.entries_with_seek()?;
        for entry in it {
            let mut entry = entry?;
            let path = entry.path()?;
            let name = path.to_string_lossy().into_owned();
            if name == ARCHIVE_MANIFEST {
                let data = read_entry_data(&mut entry)?;
                let manifest_entry: Manifest = serde_json::from_slice(&data)?;
                manifest = Some(manifest_entry);
            } else {
                println!("{:#?}", path.display()); 
                self.entries.insert(
                   path.into_owned(), read_entry_data(&mut entry)?); 
            }
        }
        Ok(manifest.ok_or_else(|| Error::NoArchiveManifest)?)
    }
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
        deflate(tarball.as_slice(), &mut tar_gz)?;

        //std::fs::write("mock.tar.gz", &tar_gz)?;

        // Decompress and extract
        let mut archive = Vec::new();
        inflate(tar_gz.as_slice(), &mut archive)?;

        let mut reader = Reader::new(Cursor::new(archive));
        let manifest = reader.prepare()?;

        println!("{:#?}", manifest);

        for (id, _) in manifest.vaults {
            println!("{}", id);
        }

        Ok(())
    }
}
