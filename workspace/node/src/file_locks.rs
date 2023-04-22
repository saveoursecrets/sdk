//! Type for getting exclusive file locks.
use crate::{Error, Result};
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

/// Manages a collection of exclusive file locks.
///
/// This prevents server process' possibly running on
/// other ports from writing to the files concurrently.
///
/// It does not prevent other programs from writing to those
/// files and corrupting the data.
#[derive(Default)]
pub struct FileLocks {
    /// Maps source files to their `.lock` file equivalents
    files: HashMap<PathBuf, PathBuf>,
    /// Keep the guards in memory to maintain the locks.
    guards: HashMap<PathBuf, LockGuard>,
}

impl FileLocks {
    /// Create a new collection of file locks.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a guard to a locked file.
    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let (file, lock_path) = self.lock_file(path.as_ref())?;
        if self.would_block(&file) {
            return Err(Error::FileLocked(path.as_ref().to_path_buf()));
        }
        let guard = LockGuard::lock(file)?;
        self.guards.insert(path.as_ref().to_path_buf(), guard);
        self.files.insert(path.as_ref().to_path_buf(), lock_path);
        Ok(())
    }

    /// Remove the guard on a locked file.
    pub fn remove(&mut self, path: &PathBuf) -> Result<bool> {
        let removed = self.guards.remove(path);
        if removed.is_some() {
            if let Some(lock_path) = self.files.remove(path) {
                std::fs::remove_file(lock_path)?;
            }
        }
        Ok(removed.is_some())
    }

    /// Get the paths for locked files.
    pub fn paths(&self) -> Vec<&PathBuf> {
        self.guards.keys().collect::<Vec<_>>()
    }

    /// Get the lock file for a source file.
    fn lock_file<P: AsRef<Path>>(&self, path: P) -> Result<(File, PathBuf)> {
        let mut lock_file = path.as_ref().to_path_buf();
        let ext = "lock";
        let extension = if let Some(file_ext) = path.as_ref().extension() {
            format!("{}.{}", file_ext.to_string_lossy(), ext)
        } else {
            ext.to_owned()
        };
        lock_file.set_extension(&extension);
        Ok((File::create(&lock_file)?, lock_file))
    }

    /// Determine if attempting to acquire a file lock would block
    /// the process.
    fn would_block(&self, file: &File) -> bool {
        file_guard::try_lock(file, Lock::Exclusive, 0, 1).is_err()
    }
}

#[self_referencing]
struct LockGuard {
    file: std::fs::File,
    #[borrows(file)]
    #[covariant]
    guard: FileGuard<&'this std::fs::File>,
}

impl LockGuard {
    pub fn lock(file: File) -> Result<Self> {
        let guard = LockGuardBuilder {
            file,
            guard_builder: |data| match file_guard::try_lock(
                data,
                Lock::Exclusive,
                0,
                1,
            ) {
                Ok(guard) => guard,
                Err(_) => panic!("file is already locked"),
            },
        }
        .build();
        Ok(guard)
    }
}
