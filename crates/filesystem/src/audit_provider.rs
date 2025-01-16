//! File system audit log file and provider.
use crate::formats::{
    read_file_identity_bytes, FileItem, FileRecord, FormatStream,
};
use crate::Result;
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter};
use binary_stream::futures::{Decodable, Encodable};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use futures::io::{BufReader, BufWriter, Cursor};
use sos_audit::{AuditEvent, AuditSink};
use sos_core::{constants::AUDIT_IDENTITY, encoding::encoding_options};
use sos_vfs::{self as vfs, File};
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Stream of records in an audit file.
pub async fn audit_stream<P: AsRef<Path>>(
    path: P,
    reverse: bool,
) -> Result<FormatStream<FileRecord, Compat<File>>> {
    read_file_identity_bytes(path.as_ref(), &AUDIT_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    Ok(FormatStream::<FileRecord, Compat<File>>::new_file(
        read_stream,
        &AUDIT_IDENTITY,
        false,
        None,
        reverse,
    )
    .await?)
}

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

    /// Encodable an audit log event record.
    async fn encode_row<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        writer: &mut BinaryWriter<W>,
        event: &AuditEvent,
    ) -> Result<()> {
        // Set up the leading row length
        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        // Encodable the event data for the row
        event.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.stream_position().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(SeekFrom::Start(row_pos)).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    /// Decodable an audit log event record.
    async fn decode_row<R: AsyncRead + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
    ) -> Result<AuditEvent> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let mut event: AuditEvent = Default::default();
        event.decode(&mut *reader).await?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32().await?;
        Ok(event)
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
pub struct AuditFileProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    file_path: PathBuf,
    marker: std::marker::PhantomData<E>,
}

impl<E> AuditFileProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new audit file provider.
    pub fn new(file_path: impl AsRef<Path>) -> Self {
        Self {
            file_path: file_path.as_ref().to_owned(),
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<E> AuditSink for AuditFileProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn append_audit_events(
        &self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error> {
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
