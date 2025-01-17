//! File system audit log file and provider.
use crate::formats::{
    read_file_identity_bytes, FileItem, FileRecord, FormatStream,
    FormatStreamIterator,
};
use crate::Result;
use async_fd_lock::{LockRead, LockWrite};
use async_stream::try_stream;
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter};
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_audit::{AuditEvent, AuditStreamSink};
use sos_core::{constants::AUDIT_IDENTITY, encoding::encoding_options};
use sos_vfs::{self as vfs, File};
use std::io::Cursor;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, BufReader, BufWriter};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Represents an audit log file.
struct AuditLogFile {
    file_path: PathBuf,
}

impl AuditLogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let file_path = path.as_ref().to_path_buf();
        Self { file_path }
    }

    /// Log file path.
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
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

    /// Read an event from a file.
    pub async fn read_event(
        &mut self,
        record: &FileRecord,
    ) -> Result<AuditEvent> {
        let file = File::open(&self.file_path).await?;
        let mut guard = file.lock_read().await.map_err(|e| e.error)?;

        let offset = record.offset();
        let row_len = offset.end - offset.start;
        guard.seek(SeekFrom::Start(offset.start)).await?;
        let mut buf = vec![0u8; row_len as usize];
        guard.read_exact(&mut buf).await?;

        let mut stream = BufReader::new(Cursor::new(&buf));
        let mut reader = BinaryReader::new(&mut stream, encoding_options());
        Ok(Self::decode_row(&mut reader).await?)
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
    file: Arc<Mutex<AuditLogFile>>,
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
        let file =
            Arc::new(Mutex::new(AuditLogFile::new(file_path.as_ref())));
        Self {
            file,
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<E> AuditStreamSink for AuditFileProvider<E>
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

        let file = self.file.lock().await;
        let file_path = file.file_path().to_owned();

        let mut file = vfs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&file_path)
            .await?;

        let size = file.metadata().await?.len();
        if size == 0 {
            file.write_all(&AUDIT_IDENTITY).await?;
            file.flush().await?;
        }

        let mut guard = file.lock_write().await.map_err(|e| e.error)?;
        guard.write_all(&buffer).await?;
        guard.flush().await?;

        Ok(())
    }

    async fn audit_stream(
        &self,
        reverse: bool,
    ) -> std::result::Result<
        BoxStream<'static, std::result::Result<AuditEvent, Self::Error>>,
        Self::Error,
    > {
        let file_path = {
            let file = self.file.lock().await;
            file.file_path().to_owned()
        };
        read_file_identity_bytes(&file_path, &AUDIT_IDENTITY).await?;
        let read_stream = File::open(file_path).await?;
        let mut it = FormatStream::<FileRecord, File>::new_file(
            read_stream,
            &AUDIT_IDENTITY,
            false,
            None,
            reverse,
        )
        .await?;

        let it_file = self.file.clone();
        Ok(Box::pin(try_stream! {
            while let Some(record) = it.next().await? {
                let mut inner = it_file.lock().await;
                let event = inner.read_event(&record).await?;
                yield event;
            }
        }))
    }
}
