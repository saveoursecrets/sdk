use async_trait::async_trait;
use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{
    constants::AUDIT_IDENTITY,
    formats::{audit_iter, FileItem, FileRecord, ReadStreamIterator},
    Result,
};

use super::{AuditEvent, AuditProvider};

use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode, Endian,
};

/// Represents an audit log file.
pub struct AuditLogFile {
    file: File,
    file_path: PathBuf,
}

impl AuditLogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let file = AuditLogFile::create(path.as_ref())?;
        let file = File::from_std(file);
        Ok(Self { file, file_path })
    }

    /// Get an audit log file iterator.
    pub fn iter(&self) -> Result<ReadStreamIterator<std::fs::File, FileRecord>> {
        audit_iter(&self.file_path)
    }

    /// Create the file used to store audit logs.
    fn create<P: AsRef<Path>>(path: P) -> Result<std::fs::File> {
        let exists = path.as_ref().exists();

        if !exists {
            let file = std::fs::File::create(path.as_ref())?;
            drop(file);
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(path.as_ref())?;

        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all(&AUDIT_IDENTITY)?;
        }

        Ok(file)
    }

    /// Read an event from a file.
    pub fn read_event(
        &self,
        file: &mut std::fs::File,
        record: &FileRecord,
    ) -> Result<AuditEvent> {
        let offset = record.offset();
        let row_len = offset.end - offset.start;
        file.seek(SeekFrom::Start(offset.start))?;
        let mut buf = vec![0u8; row_len as usize];
        file.read_exact(&mut buf)?;

        let mut stream = Cursor::new(&buf);
        let mut reader = BinaryReader::new(&mut stream, Endian::Little);
        Ok(AuditLogFile::decode_row(&mut reader)?)
    }

    /// Encode an audit log event record.
    fn encode_row<W: Write + Seek>(
        writer: &mut BinaryWriter<W>,
        event: &AuditEvent,
    ) -> BinaryResult<()> {
        // Set up the leading row length
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        // Encode the event data for the row
        event.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32)?;

        Ok(())
    }

    /// Decode an audit log event record.
    fn decode_row<R: Read + Seek>(
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<AuditEvent> {
        // Read in the row length
        let _ = reader.read_u32()?;

        let mut event: AuditEvent = Default::default();
        event.decode(&mut *reader)?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32()?;
        Ok(event)
    }
}

#[async_trait]
impl AuditProvider for AuditLogFile {
    type Error = crate::Error;

    async fn append_audit_events(
        &mut self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error> {
        let buffer: Vec<u8> = {
            let mut buffer = Vec::new();
            let mut stream = Cursor::new(&mut buffer);
            let mut writer = BinaryWriter::new(&mut stream, Endian::Little);
            for event in events {
                AuditLogFile::encode_row(&mut writer, event)?;
            }
            buffer
        };

        self.file.write_all(&buffer).await?;
        Ok(())
    }
}
