use std::io::{self, ErrorKind};
use std::{path::Path, sync::Arc};

use super::{
    fs::{create_file, resolve, MemoryFd},
    File, PathTarget,
};
use bitflags::bitflags;

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
        self.0.set(OpenFlags::READ, read);
        self
    }

    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::WRITE, write);
        self
    }

    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::APPEND, append);
        self
    }

    /// Sets the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::TRUNCATE, truncate);
        self
    }

    /// Sets the option for creating a new file.
    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::CREATE, create);
        self
    }

    /// Sets the option to always create a new file.
    pub fn create_new(&mut self, create_new: bool) -> &mut OpenOptions {
        self.0.set(OpenFlags::CREATE_NEW, create_new);
        self
    }

    /// Opens a file at `path` with the options specified by `self`.
    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        if let Some(target) = resolve(path.as_ref().to_path_buf()).await {
            match target {
                PathTarget::Descriptor(file) => {
                    if self.0.contains(OpenFlags::TRUNCATE) {
                        let mut fd = file.write().await;
                        if let MemoryFd::File(file) = &mut *fd {
                            file.truncate();
                        }
                    }

                    let is_file = {
                        let fd = file.read().await;
                        matches!(&*fd, MemoryFd::File(_))
                    };

                    if is_file {
                        let file = Arc::clone(&file);
                        File::new(file, self.0).await
                    } else {
                        Err(ErrorKind::PermissionDenied.into())
                    }
                }
                _ => Err(ErrorKind::PermissionDenied.into()),
            }
        } else {
            if self.0.contains(OpenFlags::CREATE) {
                let file = create_file(path.as_ref(), true).await?;
                File::new(file, self.0).await
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        }
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}
