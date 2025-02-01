use super::types::ManifestVersion3;
use crate::archive::Result;
use async_zip::{
    tokio::{read::seek::ZipFileReader, write::ZipFileWriter},
    Compression, ZipDateTimeBuilder, ZipEntryBuilder,
};
use sos_core::{
    constants::{ARCHIVE_MANIFEST, BLOBS_DIR},
    AccountId, ExternalFile, ExternalFileName, SecretId, SecretPath, VaultId,
};
use std::{collections::HashMap, path::PathBuf};
use time::OffsetDateTime;
use tokio::io::{AsyncBufRead, AsyncSeek, AsyncWrite};
use tokio_util::compat::Compat;

/// Write to an archive.
pub(crate) struct Writer<W: AsyncWrite + Unpin> {
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
pub(crate) struct Reader<R: AsyncBufRead + AsyncSeek + Unpin> {
    archive: ZipFileReader<R>,
}

impl<R: AsyncBufRead + AsyncSeek + Unpin> Reader<R> {
    /// Create a new reader.
    pub async fn new(inner: R) -> Result<Self> {
        Ok(Self {
            archive: ZipFileReader::with_tokio(inner).await?,
        })
    }

    /// Find an entry by name.
    pub async fn by_name(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
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

    /// Try to find the manifest in the zip archive.
    pub async fn find_manifest(
        &mut self,
    ) -> Result<Option<ManifestVersion3>> {
        if let Some(buffer) = self.by_name(ARCHIVE_MANIFEST).await? {
            let manifest_entry: ManifestVersion3 =
                serde_json::from_slice(&buffer)?;
            return Ok(Some(manifest_entry));
        }
        Ok(None)
    }

    /// Find blobs embedded in the archive.
    pub fn find_blobs(
        &mut self,
    ) -> Result<HashMap<AccountId, Vec<ExternalFile>>> {
        let mut out = HashMap::new();
        for index in 0..self.archive.file().entries().len() {
            let entry = self.archive.file().entries().get(index).unwrap();
            let is_dir = entry.dir()?;
            if !is_dir {
                let file_name = entry.filename();
                let path = sanitize_file_path(file_name.as_str()?);
                let mut it = path.iter();
                if let (
                    Some(first),
                    Some(second),
                    Some(third),
                    Some(fourth),
                    Some(fifth),
                ) = (it.next(), it.next(), it.next(), it.next(), it.next())
                {
                    if first == BLOBS_DIR {
                        if let Ok(account_id) =
                            second.to_string_lossy().parse::<AccountId>()
                        {
                            let files =
                                out.entry(account_id).or_insert(Vec::new());

                            if let (
                                Ok(folder_id),
                                Ok(secret_id),
                                Ok(file_name),
                            ) = (
                                third.to_string_lossy().parse::<VaultId>(),
                                fourth.to_string_lossy().parse::<SecretId>(),
                                fifth
                                    .to_string_lossy()
                                    .parse::<ExternalFileName>(),
                            ) {
                                files.push(ExternalFile::new(
                                    SecretPath(folder_id, secret_id),
                                    file_name,
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
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
