use std::io::{self, ErrorKind};
use std::{path::Path, sync::Arc};

use super::{File, MemoryFd, FILE_SYSTEM, FS_LOCK};
use bitflags::bitflags;
use once_cell::sync::Lazy;
use tokio::sync::{Mutex, RwLock};

bitflags! {
    /// Bit flags for the open options.
    #[derive(Default)]
    pub struct OpenFlags: u8 {
        const READ              =        0b00000001;
        const WRITE             =        0b00000010;
        const APPEND            =        0b00000100;
        const TRUNCATE          =        0b00001000;
        const CREATE            =        0b00010000;
        const CREATE_NEW        =        0b00100000;
    }
}

/// Options and flags which can be used to configure how a file is opened.
#[derive(Clone, Debug)]
pub struct OpenOptions(OpenFlags);

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> OpenOptions {
        OpenOptions(Default::default())
    }

    /// Sets the option for read access.
    pub fn read(&mut self, read: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::READ, true);
        self
    }

    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::WRITE, true);
        self
    }

    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::APPEND, true);
        self
    }

    /// Sets the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::TRUNCATE, true);
        self
    }

    /// Sets the option for creating a new file.
    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::CREATE, true);
        self
    }

    /// Sets the option to always create a new file.
    pub fn create_new(&mut self, create_new: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::CREATE_NEW, true);
        self
    }

    /// Opens a file at `path` with the options specified by `self`.
    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        unsafe {
            let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
            let file = if let Some(file) = fs.get(path.as_ref()) {
                if self.0.contains(OpenFlags::TRUNCATE) {
                    let mut fd = file.write().await;
                    if let MemoryFd::File(file) = &mut *fd {
                        file.contents = Vec::new();
                    }
                }

                let (is_file, length) = {
                    let fd = file.read().await;
                    if let MemoryFd::File(file) = &*fd {
                        (true, file.len())
                    } else {
                        (false, 0)
                    }
                };

                if is_file {
                    let file = Arc::clone(&file);
                    (file, length).into()
                } else {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            } else {
                if self.0.contains(OpenFlags::CREATE) {
                    let path = path.as_ref().to_path_buf();
                    let _ = FS_LOCK.lock().await;
                    let fd = fs.entry(path).or_insert_with(|| {
                        Arc::new(RwLock::new(MemoryFd::File(
                            Default::default(),
                        )))
                    });

                    let file = Arc::clone(&*fd);
                    (file, 0).into()
                } else {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            };
            Ok(file)
        }
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}
