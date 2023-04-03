//! Read and write archives of vaults.
//!
//! Designed to avoid file system operations so it can
//! also be used from webassembly.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use time::OffsetDateTime;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    constants::{ARCHIVE_MANIFEST, FILES_DIR, VAULT_EXT},
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
            .compression_method(CompressionMethod::Deflated);
        let (hours, minutes, seconds) = now.time().as_hms();
        let dt = zip::DateTime::from_date_and_time(
            now.year().try_into()?,
            now.month().into(),
            now.day(),
            hours,
            minutes,
            seconds,
        )
        .map_err(|_| Error::ZipDateTime)?;
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
            hex::encode(Sha256::digest(vault).as_slice());
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )?;

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

        let checksum = hex::encode(Sha256::digest(vault).as_slice());
        self.manifest.vaults.insert(vault_id, checksum);

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )?;

        Ok(self)
    }

    /// Add a file to the archive.
    pub fn add_file(mut self, path: &str, content: &[u8]) -> Result<Self> {
        self.append_file_buffer(path, content)?;
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
}

impl<R: Read + Seek> Reader<R> {
    /// Create a new reader.
    pub fn new(inner: R) -> Result<Self> {
        Ok(Self {
            archive: ZipArchive::new(inner)?,
            manifest: None,
        })
    }

    /// Get the manifest.
    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
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
        let entry_name = format!("{}.{}", manifest.address, VAULT_EXT);
        let checksum = hex::decode(&manifest.checksum)?;
        let (identity, _) = self.archive_entry(&entry_name, checksum)?;

        let mut vaults = Vec::with_capacity(manifest.vaults.len());
        for (k, v) in &manifest.vaults {
            let entry_name = format!("{}.{}", k, VAULT_EXT);
            let checksum = hex::decode(v)?;
            let (summary, _) = self.archive_entry(&entry_name, checksum)?;
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
        if let Ok(mut file) = self.archive.by_name(ARCHIVE_MANIFEST) {
            let mut data = Vec::new();
            std::io::copy(&mut file, &mut data)?;
            let manifest_entry: Manifest = serde_json::from_slice(&data)?;
            Ok(Some(manifest_entry))
        } else {
            Ok(None)
        }
    }

    fn archive_entry(
        &mut self,
        name: &str,
        checksum: Vec<u8>,
    ) -> Result<ArchiveItem> {
        let mut file = self.archive.by_name(name)?;
        let mut data = Vec::new();
        std::io::copy(&mut file, &mut data)?;

        let digest = Sha256::digest(&data);
        if checksum != digest.to_vec() {
            return Err(Error::ArchiveChecksumMismatch(name.to_string()));
        }
        let summary = VaultHeader::read_summary_slice(&data)?;
        Ok((summary, data))
    }

    /// Extract files to a destination.
    pub fn extract_files<P: AsRef<Path>>(
        &mut self,
        target: P,
        selected: &[Summary],
    ) -> Result<()> {
        for i in 0..self.archive.len() {
            let mut file = self.archive.by_index(i)?;
            if file.is_file() {
                if let Some(name) = file.enclosed_name() {
                    let path = PathBuf::from(name);
                    let mut it = path.iter();
                    if let (Some(first), Some(second)) =
                        (it.next(), it.next())
                    {
                        if first == FILES_DIR {
                            let vault_id: VaultId =
                                second.to_string_lossy().parse()?;

                            // Only restore files for the selected vaults
                            if selected
                                .iter()
                                .find(|s| s.id() == &vault_id)
                                .is_some()
                            {
                                // The given target path should already
                                // include any files/ prefix so we need
                                // to skip it
                                let mut relative = PathBuf::new();
                                for part in path.iter().skip(1) {
                                    relative = relative.join(part);
                                }
                                let destination =
                                    target.as_ref().join(relative);
                                if let Some(parent) = destination.parent() {
                                    if !parent.exists() {
                                        std::fs::create_dir_all(parent)?;
                                    }
                                }
                                let mut output = File::create(destination)?;
                                std::io::copy(&mut file, &mut output)?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Finish reading by validating entries against the manifest.
    ///
    /// This will verify the vault buffers match the checksums in
    /// the manifest.
    ///
    /// It also extracts the vault summaries so we are confident
    /// each buffer is a valid vault.
    pub fn finish(
        mut self,
    ) -> Result<(String, ArchiveItem, Vec<ArchiveItem>)> {
        let manifest =
            self.manifest.take().ok_or(Error::NoArchiveManifest)?;
        let entry_name = format!("{}.{}", manifest.address, VAULT_EXT);
        let checksum = hex::decode(manifest.checksum)?;
        let identity = self.archive_entry(&entry_name, checksum)?;
        let mut vaults = Vec::new();

        for (k, v) in manifest.vaults {
            let entry_name = format!("{}.{}", k, VAULT_EXT);
            let checksum = hex::decode(v)?;
            vaults.push(self.archive_entry(&entry_name, checksum)?);
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
