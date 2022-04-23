use async_trait::async_trait;
use std::path::Path;
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};

use crate::Result;
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
use sos_core::{
    audit::{Append, Log},
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
    guard: LockGuard,
}

impl LogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = LogFile::create(path.as_ref())?;
        let file = File::from_std(file);
        Ok(Self {
            file: Mutex::new(file),
            guard: LockGuard::lock(path)?,
        })
    }

    /// Create the file used to store audit logs.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<std::fs::File> {
        let exists = path.as_ref().exists();

        if !exists {
            let file = std::fs::File::create(path.as_ref())?;
            drop(file);
        }

        let file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(path.as_ref())?;

        if !exists {
            // TODO: if file didn't exist then write the audit identity bytes
        }
        Ok(file)
    }

    /// Determine if attempting to acquire a file lock would block
    /// the process.
    pub fn would_block<P: AsRef<Path>>(path: P) -> Result<bool> {
        let file = LogFile::create(path.as_ref())?;
        let blocks = match file_guard::try_lock(&file, Lock::Exclusive, 0, 1) {
            Ok(_) => false,
            Err(_) => true,
        };
        Ok(blocks)
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
        writer.sync_all().await?;
        Ok(())
    }
}

#[self_referencing]
struct LockGuard {
    lock: std::fs::File,
    #[borrows(lock)]
    #[covariant]
    guard: FileGuard<&'this std::fs::File>,
}

impl LockGuard {
    pub fn lock<P: AsRef<Path>>(path: P) -> Result<Self> {
        let guard = LockGuardBuilder {
            lock: std::fs::File::create(path)?,
            guard_builder: |data| match file_guard::try_lock(
                data,
                Lock::Exclusive,
                0,
                1,
            ) {
                Ok(guard) => guard,
                Err(_) => panic!("audit log is already locked"),
            },
        }
        .build();
        Ok(guard)
    }
}
