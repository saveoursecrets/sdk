use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use async_zip::{
    tokio::{read::seek::ZipFileReader, write::ZipFileWriter},
    Compression, ZipDateTimeBuilder, ZipEntryBuilder,
};

use tokio::io::{AsyncBufRead, AsyncSeek, AsyncWrite};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use sos_sdk::{
    archive::{ArchiveItem, Manifest},
    constants::{
        ACCOUNT_EVENTS, ARCHIVE_MANIFEST, DEVICE_FILE, EVENT_LOG_EXT,
        FILES_DIR, FILE_EVENTS, JSON_EXT, PREFERENCES_FILE, REMOTES_FILE,
        VAULT_EXT,
    },
    hex,
    signer::ecdsa::Address,
    vault::{Header as VaultHeader, Summary, VaultId},
    vfs::{self, File},
};

use crate::{Error, Result};

/// Write to an archive.
///
/// Creating archives assumes the vault buffers have already been
/// verified to be valid vaults.
pub struct Writer<W: AsyncWrite + Unpin> {
    writer: ZipFileWriter<W>,
    manifest: Manifest,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Create a new writer.
    pub fn new(inner: W) -> Self {
        Self {
            writer: ZipFileWriter::with_tokio(inner),
            manifest: Default::default(),
        }
    }

    async fn append_file_buffer(
        &mut self,
        path: &str,
        buffer: &[u8],
    ) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let (hours, minutes, seconds) = now.time().as_hms();
        let month: u8 = now.month().into();

        let dt = ZipDateTimeBuilder::new()
            .year(now.year().into())
            .month(month.into())
            .day(now.day().into())
            .hour(hours.into())
            .minute(minutes.into())
            .second(seconds.into())
            .build();

        let entry = ZipEntryBuilder::new(path.into(), Compression::Deflate)
            .last_modification_date(dt);
        self.writer.write_entry_whole(entry, buffer).await?;
        Ok(())
    }

    /// Set the identity vault for the archive.
    pub async fn set_identity(
        mut self,
        address: &Address,
        vault: &[u8],
    ) -> Result<Self> {
        let mut path = PathBuf::from(address.to_string());
        path.set_extension(VAULT_EXT);

        self.manifest.address = *address;
        self.manifest.checksum =
            hex::encode(Sha256::digest(vault).as_slice());
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )
        .await?;

        Ok(self)
    }

    /// Add a vault to the archive.
    pub async fn add_vault(
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
        )
        .await?;

        Ok(self)
    }

    /// Add a devices vault to the archive.
    pub async fn add_devices(
        mut self,
        vault: &[u8],
        events: &[u8],
    ) -> Result<Self> {
        let vault_checksum = hex::encode(Sha256::digest(vault).as_slice());
        let event_checksum = hex::encode(Sha256::digest(events).as_slice());
        self.manifest.devices = Some((vault_checksum, event_checksum));

        // Create the device vault file
        let mut path = PathBuf::from(DEVICE_FILE);
        path.set_extension(VAULT_EXT);
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            vault,
        )
        .await?;

        // Create the device events file
        let mut path = PathBuf::from(DEVICE_FILE);
        path.set_extension(EVENT_LOG_EXT);
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            events,
        )
        .await?;

        Ok(self)
    }

    /// Add account events to the archive.
    pub async fn add_account_events(mut self, events: &[u8]) -> Result<Self> {
        let event_checksum = hex::encode(Sha256::digest(events).as_slice());
        self.manifest.account = Some(event_checksum);

        // Create the account events file
        let mut path = PathBuf::from(ACCOUNT_EVENTS);
        path.set_extension(EVENT_LOG_EXT);
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            events,
        )
        .await?;

        Ok(self)
    }

    /// Add file events to the archive.
    pub async fn add_file_events(mut self, events: &[u8]) -> Result<Self> {
        let event_checksum = hex::encode(Sha256::digest(events).as_slice());
        self.manifest.files = Some(event_checksum);

        // Create the file events file
        let mut path = PathBuf::from(FILE_EVENTS);
        path.set_extension(EVENT_LOG_EXT);
        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            events,
        )
        .await?;

        Ok(self)
    }

    /// Add account-specific preferences.
    pub async fn add_preferences(mut self, prefs: &[u8]) -> Result<Self> {
        let checksum = hex::encode(Sha256::digest(prefs).as_slice());
        self.manifest.preferences = Some(checksum);

        // Create the file events file
        let mut path = PathBuf::from(PREFERENCES_FILE);
        path.set_extension(JSON_EXT);

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            prefs,
        )
        .await?;

        Ok(self)
    }

    /// Add remote server settings.
    pub async fn add_remote_servers(
        mut self,
        remotes: &[u8],
    ) -> Result<Self> {
        let checksum = hex::encode(Sha256::digest(remotes).as_slice());
        self.manifest.remotes = Some(checksum);

        // Create the file events file
        let mut path = PathBuf::from(REMOTES_FILE);
        path.set_extension(JSON_EXT);

        self.append_file_buffer(
            path.to_string_lossy().into_owned().as_ref(),
            remotes,
        )
        .await?;

        Ok(self)
    }

    /// Add a file to the archive.
    pub async fn add_file(
        mut self,
        path: &str,
        content: &[u8],
    ) -> Result<Self> {
        self.append_file_buffer(path, content).await?;
        Ok(self)
    }

    /// Add the manifest and finish building the archive.
    pub async fn finish(mut self) -> Result<Compat<W>> {
        let manifest = serde_json::to_vec_pretty(&self.manifest)?;
        self.append_file_buffer(ARCHIVE_MANIFEST, manifest.as_slice())
            .await?;
        Ok(self.writer.close().await?)
    }
}

/// Inventory of an archive.
pub struct Inventory {
    /// The archive manifest.
    pub manifest: Manifest,
    /// Summary for the identity vault.
    pub identity: Summary,
    /// Summaries for the archived vaults.
    pub vaults: Vec<Summary>,
    /// Flag indicating whether the account referenced
    /// in the manifest already exists locally.
    pub exists_local: bool,
}

/// Read from an archive.
pub struct Reader<R: AsyncBufRead + AsyncSeek + Unpin> {
    archive: ZipFileReader<R>,
    manifest: Option<Manifest>,
}

impl<R: AsyncBufRead + AsyncSeek + Unpin> Reader<R> {
    /// Create a new reader.
    pub async fn new(inner: R) -> Result<Self> {
        Ok(Self {
            archive: ZipFileReader::with_tokio(inner).await?,
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
    pub async fn inventory(&mut self) -> Result<Inventory> {
        let manifest = self
            .find_manifest()
            .await?
            .take()
            .ok_or(Error::NoArchiveManifest)?;
        let entry_name = format!("{}.{}", manifest.address, VAULT_EXT);
        let checksum = hex::decode(&manifest.checksum)?;
        let (identity, _) =
            self.archive_folder(&entry_name, checksum).await?;

        let mut vaults = Vec::with_capacity(manifest.vaults.len());
        for (k, v) in &manifest.vaults {
            let entry_name = format!("{}.{}", k, VAULT_EXT);
            let checksum = hex::decode(v)?;
            let (summary, _) =
                self.archive_folder(&entry_name, checksum).await?;
            vaults.push(summary);
        }
        vaults.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(Inventory {
            manifest,
            identity,
            vaults,
            exists_local: false,
        })
    }

    /// Prepare the archive for reading by parsing the manifest.
    pub async fn prepare(mut self) -> Result<Self> {
        self.manifest = self.find_manifest().await?;
        Ok(self)
    }

    async fn by_name(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        for index in 0..self.archive.file().entries().len() {
            let entry = self.archive.file().entries().get(index).unwrap();
            let file_name = entry.filename();
            let file_name = file_name.as_str()?;
            if file_name == name {
                let mut reader =
                    self.archive.reader_with_entry(index).await?;

                let mut buffer = Vec::new();
                reader.read_to_end_checked(&mut buffer).await?;
                return Ok(Some(buffer));
            }
        }
        Ok(None)
    }

    async fn find_manifest(&mut self) -> Result<Option<Manifest>> {
        if let Some(buffer) = self.by_name(ARCHIVE_MANIFEST).await? {
            let manifest_entry: Manifest = serde_json::from_slice(&buffer)?;
            return Ok(Some(manifest_entry));
        }
        Ok(None)
    }

    async fn archive_folder(
        &mut self,
        name: &str,
        checksum: Vec<u8>,
    ) -> Result<ArchiveItem> {
        let data = self.by_name(name).await?.unwrap();
        let digest = Sha256::digest(&data);
        if checksum != digest.to_vec() {
            return Err(Error::ArchiveChecksumMismatch(name.to_string()));
        }
        let summary = VaultHeader::read_summary_slice(&data).await?;
        Ok((summary, data))
    }

    async fn archive_buffer(
        &mut self,
        name: &str,
        checksum: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let data = self.by_name(name).await?.unwrap();
        let digest = Sha256::digest(&data);
        if checksum != digest.to_vec() {
            return Err(Error::ArchiveChecksumMismatch(name.to_string()));
        }
        Ok(data)
    }

    /// Extract files to a destination.
    pub async fn extract_files<P: AsRef<Path>>(
        &mut self,
        target: P,
        selected: &[Summary],
    ) -> Result<()> {
        for index in 0..self.archive.file().entries().len() {
            let entry = self.archive.file().entries().get(index).unwrap();
            let is_dir = entry.dir()?;

            if !is_dir {
                let file_name = entry.filename();

                let path = sanitize_file_path(file_name.as_str()?);
                let mut it = path.iter();
                if let (Some(first), Some(second)) = (it.next(), it.next()) {
                    if first == FILES_DIR {
                        if let Ok(vault_id) =
                            second.to_string_lossy().parse::<VaultId>()
                        {
                            // Only restore files for the selected vaults
                            if selected.iter().any(|s| s.id() == &vault_id) {
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
                                    if !vfs::try_exists(&parent).await? {
                                        vfs::create_dir_all(parent).await?;
                                    }
                                }

                                let mut reader = self
                                    .archive
                                    .reader_without_entry(index)
                                    .await?;
                                let output =
                                    File::create(destination).await?;
                                futures_util::io::copy(
                                    &mut reader,
                                    &mut output.compat_write(),
                                )
                                .await?;
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
    /// This will verify the buffers match the checksums in
    /// the manifest.
    ///
    /// It also extracts the vault summaries so we are confident
    /// each buffer is a valid vault.
    pub async fn finish(
        mut self,
    ) -> Result<(
        Manifest,
        ArchiveItem,
        Vec<ArchiveItem>,
        Option<(ArchiveItem, Vec<u8>)>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    )> {
        let manifest =
            self.manifest.take().ok_or(Error::NoArchiveManifest)?;
        let entry_name = format!("{}.{}", manifest.address, VAULT_EXT);
        let checksum = hex::decode(&manifest.checksum)?;
        let identity = self.archive_folder(&entry_name, checksum).await?;
        let mut vaults = Vec::new();

        for (k, v) in &manifest.vaults {
            let entry_name = format!("{}.{}", k, VAULT_EXT);
            let checksum = hex::decode(v)?;
            vaults.push(self.archive_folder(&entry_name, checksum).await?);
        }

        let devices = if let Some((vault_checksum, event_checksum)) =
            &manifest.devices
        {
            let devices_vault_name = format!("{}.{}", DEVICE_FILE, VAULT_EXT);
            let devices_event_name =
                format!("{}.{}", DEVICE_FILE, EVENT_LOG_EXT);
            let devices_vault = self
                .archive_folder(
                    &devices_vault_name,
                    hex::decode(&vault_checksum)?,
                )
                .await?;
            let devices_event = self
                .archive_buffer(
                    &devices_event_name,
                    hex::decode(event_checksum)?,
                )
                .await?;
            Some((devices_vault, devices_event))
        } else {
            None
        };

        let account = if let Some(checksum) = &manifest.account {
            let name = format!("{}.{}", ACCOUNT_EVENTS, EVENT_LOG_EXT);
            let events =
                self.archive_buffer(&name, hex::decode(checksum)?).await?;
            Some(events)
        } else {
            None
        };

        let files = if let Some(checksum) = &manifest.files {
            let name = format!("{}.{}", FILE_EVENTS, EVENT_LOG_EXT);
            let events =
                self.archive_buffer(&name, hex::decode(checksum)?).await?;
            Some(events)
        } else {
            None
        };

        let prefs = if let Some(checksum) = &manifest.preferences {
            let name = format!("{}.{}", PREFERENCES_FILE, JSON_EXT);
            let events =
                self.archive_buffer(&name, hex::decode(checksum)?).await?;
            Some(events)
        } else {
            None
        };

        let remotes = if let Some(checksum) = &manifest.remotes {
            let name = format!("{}.{}", REMOTES_FILE, JSON_EXT);
            let events =
                self.archive_buffer(&name, hex::decode(checksum)?).await?;
            Some(events)
        } else {
            None
        };

        Ok((
            manifest, identity, vaults, devices, account, files, prefs,
            remotes,
        ))
    }
}

/// Returns a relative path without reserved names,
/// redundant separators, ".", or "..".
fn sanitize_file_path(path: &str) -> PathBuf {
    // Replaces backwards slashes
    path.replace('\\', "/")
        // Sanitizes each component
        .split('/')
        .map(sanitize_filename::sanitize)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use sos_sdk::{encode, identity::IdentityFolder, vault::Vault, Paths};
    use std::io::Cursor;

    #[tokio::test]
    async fn archive_buffer_async() -> Result<()> {
        let mut archive = Vec::new();
        let writer = Writer::new(Cursor::new(&mut archive));
        let dir = tempfile::tempdir()?;

        Paths::scaffold(Some(dir.path().to_owned())).await?;

        let identity_vault = IdentityFolder::new(
            "Mock".to_string(),
            "mock-password".to_string().into(),
            Some(dir.path().to_owned()),
        )
        .await?;
        let address = identity_vault.address().clone();
        let identity_vault: Vault = identity_vault.into();

        let identity = encode(&identity_vault).await?;

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault).await?;

        let zip = writer
            .set_identity(&address, &identity)
            .await?
            .add_vault(*vault.id(), &vault_buffer)
            .await?
            .finish()
            .await?;

        let expected_vault_entries =
            vec![(vault.summary().clone(), vault_buffer)];

        // Decompress and extract
        let cursor = zip.into_inner();
        let mut reader = Reader::new(Cursor::new(cursor.get_ref())).await?;
        let inventory = reader.inventory().await?;

        assert_eq!(address, inventory.manifest.address);
        assert_eq!("Mock", inventory.identity.name());
        assert_eq!(1, inventory.vaults.len());

        let (manifest_decoded, identity_entry, vault_entries, _, _, _, _, _) =
            reader.prepare().await?.finish().await?;

        assert_eq!(address, manifest_decoded.address);

        let (identity_summary, identity_buffer) = identity_entry;
        assert_eq!(identity_vault.summary(), &identity_summary);
        assert_eq!(identity, identity_buffer);
        assert_eq!(expected_vault_entries, vault_entries);

        Ok(())
    }
}
