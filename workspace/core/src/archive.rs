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

use zip::{ZipWriter, CompressionMethod, write::FileOptions};
use time::OffsetDateTime;

use crate::{
    constants::{ARCHIVE_MANIFEST, VAULT_EXT},
    vault::{Header as VaultHeader, Summary, VaultId},
    Error, Result,
};

/*
/// Finish the header in a TAR archive for a regular file.
pub(crate) fn finish_header(header: &mut Header) {
    let now = OffsetDateTime::now_utc();
    header.set_entry_type(EntryType::Regular);
    header.set_mtime(now.unix_timestamp() as u64);
    header.set_mode(0o755);
    header.set_cksum();
}

/// Borrowed for the tar crate source so we can support long names
/// when creating entries.
fn prepare_header(size: u64, entry_type: u8) -> Header {
    let mut header = Header::new_gnu();
    let name = b"././@LongLink";
    header.as_gnu_mut().unwrap().name[..name.len()]
        .clone_from_slice(&name[..]);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    // + 1 to be compliant with GNU tar
    header.set_size(size + 1);
    header.set_entry_type(EntryType::new(entry_type));
    header.set_cksum();
    header
}

/// Append a buffer using a long path entry.
pub fn append_long_path<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    buffer: &[u8],
) -> Result<()> {
    //let path = format!(
    //"{}/{}", file_path, hex::encode(checksum));

    // Prepare long path header
    let path_header = prepare_header(path.len() as u64, b'L');
    // Add entry for the long path data
    builder.append(&path_header, path.as_bytes())?;

    // Add a standard header for the file data
    let mut header = Header::new_gnu();
    header.set_size(buffer.len() as u64);
    finish_header(&mut header);
    builder.append(&header, buffer)?;

    Ok(())
}
*/

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
pub struct Writer<W: Write + Seek> {
    builder: ZipWriter<W>,
    manifest: Manifest,
}

impl<W: Write + Seek> Writer<W> {
    /// Create a new writer.
    pub fn new(inner: W) -> Self {
        Self {
            builder: ZipWriter::new(inner),
            manifest: Default::default(),
        }
    }

    fn append_file_buffer(&mut self, path: &str, buffer: &[u8]) -> Result<()> {
        //let now = OffsetDateTime::now_utc();
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Stored);
        // FIXME: 
        //let options = options.last_modified_time(now.try_into()?);
        self.builder.start_file(path, options)?;
        self.builder.write(buffer)?;
        Ok(())
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
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )?;

        /*
        let mut path = PathBuf::from(&address);
        path.set_extension(VAULT_EXT);

        self.manifest.address = address;
        self.manifest.checksum =
            hex::encode(Keccak256::digest(vault).as_slice());

        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(vault.len() as u64);
        finish_header(&mut header);

        self.builder.append(&header, vault)?;
        */
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

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )?;

        Ok(self)
    }

    /// Add the manifest and finish building the tarball.
    pub fn finish(mut self) -> Result<W> {
        let path = PathBuf::from(ARCHIVE_MANIFEST);
        let manifest = serde_json::to_vec_pretty(&self.manifest)?;

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            manifest.as_slice(),
        )?;

        Ok(self.builder.finish()?)
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

/// Inventory of an archive.
pub struct Inventory {
    /// The archive manifest.
    pub manifest: Manifest,
    /// Summary for the identity vault.
    pub identity: Summary,
    /// Summaries for the archived vaults.
    pub vaults: Vec<Summary>,
}

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

    /// Read an inventory including the manifest and summary
    /// of all the vaults.
    ///
    /// This is necessary for an import process which would first
    /// need to determine the identity and which vaults might conflict
    /// with existing vaults.
    pub fn inventory(mut self) -> Result<Inventory> {
        let manifest = self
            .find_manifest()?
            .take()
            .ok_or(Error::NoArchiveManifest)?;

        let mut identity_path = PathBuf::from(&manifest.address);
        identity_path.set_extension(VAULT_EXT);
        let checksum = hex::decode(&manifest.checksum)?;
        let (identity, _) = self.archive_entry(identity_path, checksum)?;

        let mut vaults = Vec::with_capacity(manifest.vaults.len());
        for (k, v) in &manifest.vaults {
            let mut entry_path = PathBuf::from(k.to_string());
            entry_path.set_extension(VAULT_EXT);
            let checksum = hex::decode(v)?;
            let (summary, _) = self.archive_entry(entry_path, checksum)?;
            vaults.push(summary);
        }
        Ok(Inventory {
            manifest,
            identity,
            vaults,
        })
    }

    /// Prepare the archive for reading by parsing the manifest file and
    /// reading the data for other tarball entries.
    pub fn prepare(mut self) -> Result<Self> {
        self.manifest = self.find_manifest()?;
        Ok(self)
    }

    fn find_manifest(&mut self) -> Result<Option<Manifest>> {
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
                self.entries
                    .insert(path.into_owned(), read_entry_data(&mut entry)?);
            }
        }
        Ok(manifest)
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
        let writer = Writer::new(Cursor::new(&mut archive));

        let (address, identity_vault) = Identity::new_login_vault(
            "Mock".to_string(),
            SecretString::new("mock-password".to_string()),
        )?;

        let identity = encode(&identity_vault)?;

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        let zip = writer
            .set_identity(address.clone(), &identity)?
            .add_vault(*vault.id(), &vault_buffer)?
            .finish()?;

        let expected_vault_entries =
            vec![(vault.summary().clone(), vault_buffer)];

        //std::fs::write("mock.zip", zip.into_inner())?;

        // Decompress and extract
        //let mut archive = Vec::new();

        //let reader = Reader::new(Cursor::new(zip.into_inner().clone()));
        //let inventory = reader.inventory()?;

        /*
        assert_eq!(address, inventory.manifest.address);
        assert_eq!("Mock", inventory.identity.name());
        assert_eq!(1, inventory.vaults.len());

        let reader = Reader::new(Cursor::new(archive));
        let (address_decoded, identity_entry, vault_entries) =
            reader.prepare()?.finish()?;

        assert_eq!(address, address_decoded);

        let (identity_summary, identity_buffer) = identity_entry;
        assert_eq!(identity_vault.summary(), &identity_summary);
        assert_eq!(identity, identity_buffer);
        assert_eq!(expected_vault_entries, vault_entries);
        */

        Ok(())
    }
}
