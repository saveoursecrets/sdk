use async_trait::async_trait;
use std::{io::Write, path::Path};
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};

use crate::Result;
use sos_core::{
    audit::{Append, Log, IDENTITY},
    file_identity::FileIdentity,
    vault::encode,
};

/// Represents an audit log file.
///
/// The log file is backed by a `tokio::fs::File`
/// wrapped in a `tokio::sync::Mutex` and an exclusive
/// file lock is acquired.
///
/// Panics if the exclusive file lock cannot be acquired.
pub struct LogFile {
    file: Mutex<File>,
}

impl LogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = LogFile::create(path.as_ref())?;
        let file = File::from_std(file);
        Ok(Self {
            file: Mutex::new(file),
        })
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
            let identity = FileIdentity(IDENTITY);
            let buffer = encode(&identity)?;
            file.write_all(&buffer)?;
        }

        Ok(file)
    }
}

#[async_trait]
impl Append for LogFile {
    type Error = crate::Error;
    async fn append(
        &mut self,
        log: Log,
    ) -> std::result::Result<(), Self::Error> {
        let mut writer = self.file.lock().await;
        let buffer = encode(&log)?;
        writer.write_all(&buffer).await?;
        Ok(())
    }
}
