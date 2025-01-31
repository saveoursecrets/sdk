use super::types::ManifestVersion3;

use crate::archive::{Error, Result};
use async_zip::{
    tokio::{read::seek::ZipFileReader, write::ZipFileWriter},
    Compression, ZipDateTimeBuilder, ZipEntryBuilder,
};
use sos_core::constants::ARCHIVE_MANIFEST;
use std::path::PathBuf;
use time::OffsetDateTime;
use tokio::io::{AsyncBufRead, AsyncSeek, AsyncWrite};
use tokio_util::compat::Compat;

/// Write to an archive.
///
/// Creating archives assumes the vault buffers have already been
/// verified to be valid vaults.
pub struct Writer<W: AsyncWrite + Unpin> {
    writer: ZipFileWriter<W>,
    manifest: ManifestVersion3,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Create a new writer.
    pub fn new(inner: W) -> Self {
        Self {
            writer: ZipFileWriter::with_tokio(inner),
            manifest: ManifestVersion3::new_v3(),
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

    /// Add a file to the archive.
    pub async fn add_file(
        &mut self,
        path: &str,
        content: &[u8],
    ) -> Result<()> {
        tracing::debug!(
            path= %path,
            len = %content.len(),
            "create_archive::add_file"
        );
        self.append_file_buffer(path, content).await
    }

    /// Add the manifest and finish building the archive.
    pub async fn finish(mut self) -> Result<Compat<W>> {
        let manifest = serde_json::to_vec_pretty(&self.manifest)?;
        self.append_file_buffer(ARCHIVE_MANIFEST, manifest.as_slice())
            .await?;
        Ok(self.writer.close().await?)
    }
}

/// Read from an archive.
pub struct Reader<R: AsyncBufRead + AsyncSeek + Unpin> {
    archive: ZipFileReader<R>,
    manifest: Option<ManifestVersion3>,
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
    pub fn manifest(&self) -> Option<&ManifestVersion3> {
        self.manifest.as_ref()
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

    async fn find_manifest(&mut self) -> Result<Option<ManifestVersion3>> {
        if let Some(buffer) = self.by_name(ARCHIVE_MANIFEST).await? {
            let manifest_entry: ManifestVersion3 =
                serde_json::from_slice(&buffer)?;
            return Ok(Some(manifest_entry));
        }
        Ok(None)
    }

    /*
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
    */

    /// Finish reading by validating entries against the manifest.
    pub async fn finish(mut self) -> Result<(ManifestVersion3,)> {
        let manifest =
            self.manifest.take().ok_or(Error::NoArchiveManifest)?;

        todo!();

        /*
        let entry_name = format!("{}.{}", manifest.account_id, VAULT_EXT);
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
          */
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
