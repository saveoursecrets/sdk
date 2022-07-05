//! Iterator for audit log records.
use std::path::Path;

use sos_core::{
    constants::AUDIT_IDENTITY,
    events::AuditEvent,
    serde_binary::{
        binary_rw::{BinaryReader, Endian, FileStream, OpenType, SeekStream},
        Decode, Deserializer,
    },
    FileIdentity,
};

use crate::{Error, Result};

/// Iterate a file stream and yield audit event records.
pub struct AuditLogFileIterator {
    stream: FileStream,
    offset: usize,
    size: u64,
}

impl AuditLogFileIterator {
    /// Create a new log file iterator.
    pub fn new<P: AsRef<Path>>(
        path: P,
        expects_identity: bool,
    ) -> Result<Self> {
        let size = path.as_ref().metadata()?.len();
        if size == 0 {
            return Err(Error::EmptyFile(path.as_ref().to_path_buf()));
        } else if size < 4 {
            return Err(Error::FileTooSmall(path.as_ref().to_path_buf(), 4));
        }

        let stream = FileStream::new(path.as_ref(), OpenType::Open)?;
        let mut it = Self {
            stream,
            offset: 0,
            size,
        };
        if expects_identity {
            it.read_identity()?;
        }
        Ok(it)
    }

    fn deserializer(&mut self) -> Result<Deserializer<'_>> {
        let reader = BinaryReader::new(&mut self.stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(self.offset)?;
        Ok(de)
    }

    /// Attempt to read the identity bytes from the buffer and
    /// advance the offset.
    pub fn read_identity(&mut self) -> Result<()> {
        let mut de = self.deserializer()?;
        FileIdentity::read_identity(&mut de, &AUDIT_IDENTITY)?;
        self.offset = de.reader.tell()?;
        Ok(())
    }

    fn read_audit_log(&mut self) -> Result<AuditEvent> {
        let mut de = self.deserializer()?;
        let mut log: AuditEvent = Default::default();
        log.decode(&mut de)?;
        self.offset = de.reader.tell()?;
        Ok(log)
    }
}

impl Iterator for AuditLogFileIterator {
    type Item = Result<AuditEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        // WARN: this will fail on 32-bit platforms!
        let size = self.size as usize;

        if let Ok(mut de) = self.deserializer() {
            let pos = de.reader.tell().unwrap();
            if pos == size {
                // EOF
                return None;
            }
            Some(self.read_audit_log())
        } else {
            None
        }
    }
}
