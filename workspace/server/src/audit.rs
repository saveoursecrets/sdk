use std::path::Path;
use async_trait::async_trait;
use tokio::{fs::File, sync::Mutex, io::AsyncWriteExt};

use sos_core::{audit::{Log, Append}, vault::encode};
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
use crate::Result;

/// Represents an audit log file.
///
/// The log file is backed by a `tokio::fs::File`
/// wrapped in a `tokio::sync::Mutex` and an exclusive
/// file lock is acquired.
///
/// Panics if the exclusive file lock cannot be acquired.
pub struct LogFile {
    pub file: Mutex<File>,
    guard: LockGuard,
}

impl LogFile {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let std_file = std::fs::File::create(path.as_ref())?;
        let file = File::from_std(std_file);
        Ok(Self {
            file: Mutex::new(file),
            guard: LockGuard::lock(path)?,
        })
    }

    /// Determine if attempting to acquire a file lock would block
    /// the process.
    pub fn would_block<P: AsRef<Path>>(path: P) -> Result<bool> {
        let file = std::fs::File::create(path)?;
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
    async fn append(&mut self, log: Log) -> std::result::Result<(), Self::Error> {
        let buffer = encode(&log)?;
        let mut writer = self.file.lock().await;
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
            guard_builder: |data| {
                match file_guard::try_lock(data, Lock::Exclusive, 0, 1) {
                    Ok(guard) => guard,
                    Err(_) => panic!("audit log is already locked"),
                }
            },
        }
        .build();
        Ok(guard)
    }
}
