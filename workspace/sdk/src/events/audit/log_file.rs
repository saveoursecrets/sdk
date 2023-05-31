use async_trait::async_trait;
use std::{
    io::{Cursor, SeekFrom},
    path::{Path, PathBuf},
};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

use crate::{
    constants::AUDIT_IDENTITY,
    formats::{audit_stream, FileItem, FileRecord, FileStream},
    vfs::{self, File},
    Result,
};

use super::{AuditEvent, AuditProvider};

use binary_stream::{
    tokio::{BinaryReader, BinaryWriter},
    Endian,
};

/// Represents an audit log file.
pub struct AuditLogFile {
    file: File,
    file_path: PathBuf,
}

impl AuditLogFile {
    /// Create an audit log file.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let file = AuditLogFile::create(path.as_ref()).await?;
        Ok(Self { file, file_path })
    }

    /// Get an audit log file iterator.
    pub async fn iter(&self) -> Result<FileStream<FileRecord, File>> {
        audit_stream(&self.file_path).await
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
        }

        Ok(file)
    }

    /// Read an event from a file.
    pub async fn read_event(
        &self,
        file: &mut vfs::File,
        record: &FileRecord,
    ) -> Result<AuditEvent> {
        let offset = record.offset();
        let row_len = offset.end - offset.start;
        file.seek(SeekFrom::Start(offset.start)).await?;
        let mut buf = vec![0u8; row_len as usize];
        file.read_exact(&mut buf).await?;

        let mut stream = BufReader::new(Cursor::new(&buf));
        let mut reader = BinaryReader::new(&mut stream, Endian::Little);
        Ok(AuditLogFile::decode_row(&mut reader).await?)
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AuditProvider for AuditLogFile {
    type Error = crate::Error;

    async fn append_audit_events(
        &mut self,
        events: Vec<AuditEvent>,
    ) -> Result<()> {
        let buffer: Vec<u8> = {
            let mut buffer = Vec::new();
            let mut stream = Cursor::new(&mut buffer);
            let mut writer = BinaryWriter::new(&mut stream, Endian::Little);
            for event in events {
                AuditLogFile::encode_row(&mut writer, event).await?;
            }
            buffer
        };

        self.file.write_all(&buffer).await?;
        Ok(())
    }
}
