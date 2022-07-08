use async_trait::async_trait;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::Result;
use sos_core::{
    constants::AUDIT_IDENTITY,
    events::{AuditEvent, AuditProvider},
    iter::{FileIterator, FileRecord},
    serde_binary::{
        binary_rw::{BinaryWriter, Endian, MemoryStream, SeekStream},
        Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
    },
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

    /// Get a log file iterator.
    pub fn iter(&self) -> Result<FileIterator<FileRecord>> {
        Ok(FileIterator::new(&self.file_path, &AUDIT_IDENTITY, false)?)
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
}

impl AuditLogFile {
    pub fn encode_row(
        ser: &mut Serializer,
        event: &AuditEvent,
    ) -> BinaryResult<()> {
        // Set up the leading row length
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        // Encode the event data for the row
        event.encode(&mut *ser)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        ser.writer.write_u32(row_len as u32)?;

        Ok(())
    }

    pub fn decode_row(de: &mut Deserializer) -> BinaryResult<AuditEvent> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        let mut event: AuditEvent = Default::default();
        event.decode(&mut *de)?;

        // Read in the row length appended to the end of the record
        let _ = de.reader.read_u32()?;
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
            let mut stream = MemoryStream::new();
            let writer = BinaryWriter::new(&mut stream, Endian::Big);
            let mut serializer = Serializer { writer };
            for event in events {
                AuditLogFile::encode_row(&mut serializer, event)?;
            }
            stream.into()
        };

        self.file.write_all(&buffer).await?;
        Ok(())
    }
}
