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
    io::{Read, Seek, Write},
    path::PathBuf,
};
use tar::{Archive, Builder, Entry, EntryType, Header};
use time::OffsetDateTime;

use crate::{
    constants::{ARCHIVE_MANIFEST, VAULT_EXT},
    vault::{Header as VaultHeader, Summary, VaultId},
    Error, Result,
};

/// Manifest used to determine if the archive is supported
/// for import purposes.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Address of the identity file.
    pub address: String,

    /// Checksum of the identity vault.
    pub checksum: String,

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
        mut self,
        address: String,
        vault: &[u8],
    ) -> Result<Self> {
        let mut path = PathBuf::from(&address);
        path.set_extension(VAULT_EXT);

        self.manifest.address = address;
        self.manifest.checksum =
            hex::encode(Keccak256::digest(vault).as_slice());

        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(vault.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, vault)?;
        Ok(self)
    }

    /// Add a vault to the archive.
    pub fn add_vault(
        mut self,
        vault_id: VaultId,
        vault: &[u8],
    ) -> Result<Self> {
        let mut path = PathBuf::from(vault_id.to_string());
        path.set_extension(VAULT_EXT);

        let checksum = hex::encode(Keccak256::digest(vault).as_slice());
        self.manifest.vaults.insert(vault_id, checksum);

        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(vault.len() as u64);
        self.finish_header(&mut header);

        self.builder.append(&header, vault)?;
        Ok(self)
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

/// A vault reference extracted from an archive.
pub type ArchiveItem = (Summary, Vec<u8>);

/// Read from an archive.
pub struct Reader<R: Read + Seek> {
    archive: Archive<R>,
    manifest: Option<Manifest>,
    entries: HashMap<PathBuf, Vec<u8>>,
}

impl<R: Read + Seek> Reader<R> {
    /// Create a new reader.
    pub fn new(inner: R) -> Self {
        Self {
            archive: Archive::new(inner),
            manifest: None,
            entries: Default::default(),
        }
    }

    /// Prepare the archive for reading by parsing the manifest file.
    pub fn prepare(mut self) -> Result<Self> {
        let it = self.archive.entries_with_seek()?;
        for entry in it {
            let mut entry = entry?;
            let path = entry.path()?;
            let name = path.to_string_lossy().into_owned();
            if name == ARCHIVE_MANIFEST {
                let data = read_entry_data(&mut entry)?;
                let manifest: Manifest = serde_json::from_slice(&data)?;
                self.manifest = Some(manifest);
            } else {
                self.entries
                    .insert(path.into_owned(), read_entry_data(&mut entry)?);
            }
        }
        Ok(self)
    }

    fn archive_entry(
        &mut self,
        path: PathBuf,
        checksum: Vec<u8>,
    ) -> Result<ArchiveItem> {
        let (_, vault_buffer) = self
            .entries
            .remove_entry(&path)
            .ok_or_else(|| Error::NoArchiveVault(path.clone()))?;
        let digest = Keccak256::digest(&vault_buffer);
        if checksum != digest.to_vec() {
            return Err(Error::ArchiveChecksumMismatch(path));
        }
        let summary = VaultHeader::read_summary_slice(&vault_buffer)?;
        Ok((summary, vault_buffer))
    }

    /// Finish reading by validating entries against the manifest.
    ///
    /// This will verify the vault buffers match the checksums in
    /// the manifest and ignore any files in the archive entries
    /// that are not present in the manifest.
    ///
    /// It also extracts the vault summaries so we are confident
    /// each buffer is a valid vault.
    pub fn finish(
        mut self,
    ) -> Result<(String, ArchiveItem, Vec<ArchiveItem>)> {
        let manifest =
            self.manifest.take().ok_or(Error::NoArchiveManifest)?;
        let mut identity_path = PathBuf::from(&manifest.address);
        identity_path.set_extension(VAULT_EXT);
        let checksum = hex::decode(manifest.checksum)?;
        let identity = self.archive_entry(identity_path, checksum)?;
        let mut vaults = Vec::new();
        for (k, v) in manifest.vaults {
            let mut entry_path = PathBuf::from(k.to_string());
            entry_path.set_extension(VAULT_EXT);
            let checksum = hex::decode(v)?;
            vaults.push(self.archive_entry(entry_path, checksum)?);
        }
        Ok((manifest.address, identity, vaults))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{encode, identity::Identity, vault::Vault};
    use anyhow::Result;
    use secrecy::SecretString;
    use std::io::Cursor;

    #[test]
    fn archive_buffer() -> Result<()> {
        let mut archive = Vec::new();
        let writer = Writer::new(&mut archive);

        let (address, identity_vault) = Identity::new_login_vault(
            "Mock".to_string(),
            SecretString::new("mock-password".to_string()),
        )?;

        let identity = encode(&identity_vault)?;

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        let tarball = writer
            .set_identity(address.clone(), &identity)?
            .add_vault(*vault.id(), &vault_buffer)?
            .finish()?;

        let expected_vault_entries =
            vec![(vault.summary().clone(), vault_buffer)];

        let mut tar_gz = Vec::new();
        deflate(tarball.as_slice(), &mut tar_gz)?;

        //std::fs::write("mock.tar.gz", &tar_gz)?;

        // Decompress and extract
        let mut archive = Vec::new();
        inflate(tar_gz.as_slice(), &mut archive)?;

        let reader = Reader::new(Cursor::new(archive));
        let (address_decoded, identity_entry, vault_entries) =
            reader.prepare()?.finish()?;

        assert_eq!(address, address_decoded);

        let (identity_summary, identity_buffer) = identity_entry;
        assert_eq!(identity_vault.summary(), &identity_summary);
        assert_eq!(identity, identity_buffer);
        assert_eq!(expected_vault_entries, vault_entries);

        Ok(())
    }
}
