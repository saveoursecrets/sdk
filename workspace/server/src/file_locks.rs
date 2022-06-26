use crate::{Error, Result};
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

/// Attempts to acquire exclusive locks to a collection of files.
#[derive(Default)]
pub struct LockFiles {
    guards: HashMap<PathBuf, LockGuard>,
}

impl LockFiles {
    /// Create a new collection of locks files.
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempt to acquire a lock on all the source files.
    pub fn acquire<P: AsRef<Path>>(&mut self, sources: Vec<P>) -> Result<()> {
        for path in sources {
            self.add(path)?;
        }
        Ok(())
    }

    /// Add a guard to a locked file.
    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = LockFiles::lock_file(path.as_ref())?;
        if LockFiles::would_block(&file) {
            return Err(Error::FileLocked(path.as_ref().to_path_buf()));
        }
        let guard = LockGuard::lock(file)?;
        self.guards.insert(path.as_ref().to_path_buf(), guard);
        Ok(())
    }

    /// Remove the guard on a locked file.
    pub fn remove(&mut self, path: &PathBuf) -> bool {
        let removed = self.guards.remove(path);
        removed.is_some()
    }

    /// Get the paths for locked files.
    pub fn paths(&self) -> Vec<&PathBuf> {
        self.guards.keys().collect::<Vec<_>>()
    }

    /// Get the lock file for a source file.
    fn lock_file<P: AsRef<Path>>(path: P) -> Result<File> {
        let mut lock_file = path.as_ref().to_path_buf();
        let ext = "lock";
        let extension = if let Some(file_ext) = path.as_ref().extension() {
            format!("{}.{}", file_ext.to_string_lossy(), ext)
        } else {
            ext.to_owned()
        };
        lock_file.set_extension(&extension);
        Ok(File::create(lock_file)?)
    }

    /// Determine if attempting to acquire a file lock would block
    /// the process.
    fn would_block(file: &File) -> bool {
        match file_guard::try_lock(file, Lock::Exclusive, 0, 1) {
            Ok(_) => false,
            Err(_) => true,
        }
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
