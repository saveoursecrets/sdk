use crate::{ARCHIVE_MANIFEST, Result};
use async_zip::tokio::read::seek::ZipFileReader;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufRead, AsyncSeek};

/// Read from an archive.
pub struct Reader<R: AsyncBufRead + AsyncSeek + Unpin> {
    archive: ZipFileReader<R>,
}

impl<R: AsyncBufRead + AsyncSeek + Unpin> Reader<R> {
    /// Create a new reader.
    pub async fn new(inner: R) -> Result<Self> {
        Ok(Self {
            archive: ZipFileReader::with_tokio(inner).await?,
        })
    }

    /// Inner archive reader.
    pub fn inner(&self) -> &ZipFileReader<R> {
        &self.archive
    }

    /// Mutable inner archive reader.
    pub fn inner_mut(&mut self) -> &mut ZipFileReader<R> {
        &mut self.archive
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
    pub async fn find_manifest<T: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<T>> {
        if let Some(buffer) = self.by_name(ARCHIVE_MANIFEST).await? {
            let manifest_entry: T = serde_json::from_slice(&buffer)?;
            return Ok(Some(manifest_entry));
        }
        Ok(None)
    }
}
