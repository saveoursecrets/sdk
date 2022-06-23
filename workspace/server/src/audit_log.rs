use async_trait::async_trait;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};

use crate::Result;
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
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
    guard: LockGuard,
}

impl LogFile {
    /// Create an audit log file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let lock_file = LogFile::lock_file(path.as_ref());

        let file = LogFile::create(path.as_ref())?;
        let file = File::from_std(file);
        Ok(Self {
            file: Mutex::new(file),
            guard: LockGuard::lock(lock_file)?,
        })
    }

    /// Create the file used to store audit logs.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<std::fs::File> {
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

    /// Get the lock file path for an audit log.
    pub fn lock_file<P: AsRef<Path>>(path: P) -> PathBuf {
        let mut lock_file = path.as_ref().to_path_buf();
        lock_file.set_extension("lock");
        lock_file
    }

    /// Determine if attempting to acquire a file lock would block
    /// the process.
    pub fn would_block<P: AsRef<Path>>(path: P) -> Result<bool> {
        let file = LogFile::create(LogFile::lock_file(path))?;
        let blocks = match file_guard::try_lock(&file, Lock::Exclusive, 0, 1)
        {
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
