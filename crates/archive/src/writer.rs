use crate::Result;
use async_zip::{
    tokio::write::ZipFileWriter, Compression, ZipDateTimeBuilder,
    ZipEntryBuilder,
};
use time::OffsetDateTime;
use tokio::io::AsyncWrite;
use tokio_util::compat::Compat;

/// Write to an archive.
pub struct Writer<W: AsyncWrite + Unpin> {
    writer: ZipFileWriter<W>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Create a new writer with a manifest.
    pub fn new(inner: W) -> Self {
        Self {
            writer: ZipFileWriter::with_tokio(inner),
        }
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

    async fn append_file_buffer(
        &mut self,
        path: &str,
        buffer: &[u8],
    ) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let (hours, minutes, seconds) = now.time().as_hms();
        let month: u8 = now.month().into();

        let dt = ZipDateTimeBuilder::new()
            .year(now.year())
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

    /// Finish building the archive.
    pub async fn finish(self) -> Result<Compat<W>> {
        Ok(self.writer.close().await?)
    }
}
