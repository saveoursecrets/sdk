use std::io;
use std::path::Path;

use super::File;
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
        let path = path.as_ref().to_owned();
        let opts = self.clone();
        Ok((path, opts).try_into()?)
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}
