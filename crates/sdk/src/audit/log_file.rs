use async_trait::async_trait;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};

use futures::io::{BufReader, BufWriter, Cursor};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::compat::Compat;

use crate::{
    constants::AUDIT_IDENTITY,
    encoding::encoding_options,
    formats::{audit_stream, FileItem, FileRecord, FormatStream},
    vfs::{self, File},
    Result,
};

use super::{AuditEvent, AuditProvider};

use binary_stream::futures::{BinaryReader, BinaryWriter};

/// Represents an audit log file.
pub struct AuditLogFile {
    file_path: PathBuf,
}

impl AuditLogFile {
    /// Create an audit log file.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        Ok(Self { file_path })
    }

    /// Log file path.
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
    }

    /// Get an audit log file iterator.
    pub async fn iter(
        &self,
        reverse: bool,
    ) -> Result<FormatStream<FileRecord, Compat<File>>> {
        audit_stream(&self.file_path, reverse).await
    }

    /// Create the file used to store audit logs.
    async fn create<P: AsRef<Path>>(path: P) -> Result<vfs::File> {
        let mut file = vfs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(path.as_ref())
            .await?;

        let size = file.metadata().await?.len();
        if size == 0 {
            file.write_all(&AUDIT_IDENTITY).await?;
            file.flush().await?;
        }

        Ok(file)
    }

    /// Read an event from a file.
    pub async fn read_event(
        &self,
        file: &mut vfs::File,
        record: &FileRecord,
    ) -> Result<AuditEvent> {
        let buf = self.read_event_buffer(file, record).await?;
        let mut stream = BufReader::new(Cursor::new(&buf));
        let mut reader = BinaryReader::new(&mut stream, encoding_options());
        Ok(AuditLogFile::decode_row(&mut reader).await?)
    }

    /// Read the event buffer from a file.
    pub async fn read_event_buffer(
        &self,
        file: &mut vfs::File,
        record: &FileRecord,
    ) -> Result<Vec<u8>> {
        let offset = record.offset();
        let row_len = offset.end - offset.start;
        file.seek(SeekFrom::Start(offset.start)).await?;
        let mut buf = vec![0u8; row_len as usize];
        file.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[async_trait]
impl AuditProvider for AuditLogFile {
    type Error = crate::Error;

    async fn append_audit_events(
        &mut self,
        events: Vec<AuditEvent>,
    ) -> Result<()> {
        // Make a single buffer of all audit events
        let buffer: Vec<u8> = {
            let mut buffer = Vec::new();
            let mut stream = BufWriter::new(Cursor::new(&mut buffer));
            let mut writer =
                BinaryWriter::new(&mut stream, encoding_options());
            for event in events {
                AuditLogFile::encode_row(&mut writer, event).await?;
                writer.flush().await?;
            }
            buffer
        };

        let file = Self::create(&self.file_path).await?;
        let mut guard = vfs::lock_write(file).await?;
        guard.write_all(&buffer).await?;
        guard.flush().await?;

        Ok(())
    }
}
