use crate::{fs::audit_stream, Result};
use crate::{AuditEvent, AuditSink};
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter};
use futures::io::{BufReader, BufWriter, Cursor};
use sos_core::{constants::AUDIT_IDENTITY, encoding::encoding_options};
use sos_filesystem::formats::{FileItem, FileRecord, FormatStream};
use sos_vfs::{self as vfs, File};
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::compat::Compat;

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
        Ok(audit_stream(&self.file_path, reverse).await?)
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

/// Audit file provider.
pub struct AuditFileProvider {
    file_path: PathBuf,
}

impl AuditFileProvider {
    /// Create a new audit file provider.
    pub fn new(file_path: impl AsRef<Path>) -> Self {
        Self {
            file_path: file_path.as_ref().to_owned(),
        }
    }
}

#[async_trait]
impl AuditSink for AuditFileProvider {
    type Error = crate::Error;

    async fn append_audit_events(&self, events: &[AuditEvent]) -> Result<()> {
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

        let file = AuditLogFile::create(&self.file_path).await?;
        let mut guard = vfs::lock_write(file).await?;
        guard.write_all(&buffer).await?;
        guard.flush().await?;

        Ok(())
    }
}
