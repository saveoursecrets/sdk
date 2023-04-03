//! Read and write archives of vaults.
//!
//! Designed to avoid file system operations so it can
//! also be used from webassembly.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
    path::PathBuf,
};

use time::OffsetDateTime;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

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

    fn append_file_buffer(
        &mut self,
        path: &str,
        buffer: &[u8],
    ) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Stored);
        let (hours, minutes, seconds) = now.time().as_hms();
        let dt = zip::DateTime::from_date_and_time(
            now.year().try_into()?,
            now.month().into(),
            now.day(),
            hours,
            minutes,
            seconds,
        ).map_err(|_| Error::ZipDateTime)?;
        let options = options.last_modified_time(dt);
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

        Ok(self)
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

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )?;

        Ok(())
    }

    /// Add a file to the archive.
    pub fn add_file(
        &mut self,
        path: &str,
        content: &[u8],
    ) -> Result<()> {
        self.append_file_buffer(
            path,
            content,
        )?;
        Ok(())
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
    archive: ZipArchive<R>,
    manifest: Option<Manifest>,
    entries: HashMap<PathBuf, Vec<u8>>,
}

impl<R: Read + Seek> Reader<R> {
    /// Create a new reader.
    pub fn new(inner: R) -> Result<Self> {
        Ok(Self {
            archive: ZipArchive::new(inner)?,
            manifest: None,
            entries: Default::default(),
        })
    }

    /// Read an inventory including the manifest and summary
    /// of all the vaults.
    ///
    /// This is necessary for an import process which would first
    /// need to determine the identity and which vaults might conflict
    /// with existing vaults.
    pub fn inventory(&mut self) -> Result<Inventory> {
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
        vaults.sort_by(|a, b| a.name().partial_cmp(b.name()).unwrap());
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
        //let it = self.archive.entries_with_seek()?;
        for i in 0..self.archive.len() {
            let mut file = self.archive.by_index(i)?;
            if file.name() == ARCHIVE_MANIFEST {
                let mut data = Vec::new();
                std::io::copy(&mut file, &mut data)?;
                let manifest_entry: Manifest = serde_json::from_slice(&data)?;
                manifest = Some(manifest_entry);
            } else {
                let mut data = Vec::new();
                std::io::copy(&mut file, &mut data)?;
                self.entries.insert(PathBuf::from(file.name()), data);
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
        let mut reader = Reader::new(Cursor::new(zip.into_inner().clone()))?;
        let inventory = reader.inventory()?;

        assert_eq!(address, inventory.manifest.address);
        assert_eq!("Mock", inventory.identity.name());
        assert_eq!(1, inventory.vaults.len());

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
