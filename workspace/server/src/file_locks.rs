use crate::{Error, Result};
use file_guard::{FileGuard, Lock};
use ouroboros::self_referencing;
use std::{fs::File, path::Path};

/// Attempts to acquire exclusive locks to a collection of files.
#[derive(Default)]
pub struct LockFiles {
    guards: Vec<LockGuard>,
}

impl LockFiles {
    /// Create a new collection of locks files.
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempt to acquire a lock on all the source files.
    pub fn acquire<P: AsRef<Path>>(&mut self, sources: Vec<P>) -> Result<()> {
        for path in sources {
            let file = LockFiles::lock_file(path.as_ref())?;
            if LockFiles::would_block(&file) {
                return Err(Error::FileLocked(path.as_ref().to_path_buf()));
            }
            let guard = LockGuard::lock(file)?;
            self.guards.push(guard);
        }
        Ok(())
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
