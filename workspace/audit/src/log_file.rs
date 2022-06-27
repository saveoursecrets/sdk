use async_trait::async_trait;
use std::{io::Write, path::Path};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::Result;
use sos_core::{
    events::{AuditEvent, AuditProvider},
    file_identity::{FileIdentity, AUDIT_IDENTITY},
    vault::encode,
};

/// Represents an audit log file.
pub struct AuditLogFile {
    file: File,
}

impl AuditLogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = AuditLogFile::create(path.as_ref())?;
        let file = File::from_std(file);
        Ok(Self { file })
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
            let identity = FileIdentity(AUDIT_IDENTITY);
            let buffer = encode(&identity)?;
            file.write_all(&buffer)?;
        }

        Ok(file)
    }
}

#[async_trait]
impl AuditProvider for AuditLogFile {
    type Error = crate::Error;
    async fn append_audit_event(
        &mut self,
        log: AuditEvent,
    ) -> std::result::Result<(), Self::Error> {
        let buffer = encode(&log)?;
        self.file.write_all(&buffer).await?;
        Ok(())
    }
}
