use crate::{Result, ARCHIVE_MANIFEST};
use async_zip::{
    tokio::write::ZipFileWriter, Compression, ZipDateTimeBuilder,
    ZipEntryBuilder,
};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::io::AsyncWrite;
use tokio_util::compat::Compat;

/// Write to an archive.
pub struct Writer<W: AsyncWrite + Unpin, M: Serialize> {
    writer: ZipFileWriter<W>,
    manifest: M,
}

impl<W: AsyncWrite + Unpin, M: Serialize> Writer<W, M> {
    /// Create a new writer.
    pub fn new(inner: W, manifest: M) -> Self {
        Self {
            writer: ZipFileWriter::with_tokio(inner),
            manifest,
        }
    }

    /// Mutable archive manifest.
    pub fn manifest_mut(&mut self) -> &mut M {
        &mut self.manifest
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
}
