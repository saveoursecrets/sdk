use super::FileFlags;
use std::io;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use std::time::SystemTime;

/// Representation of the various permissions on a file.
#[derive(Debug, Default, Copy, Clone)]
pub struct Permissions {
    read_only: bool,
}

impl Permissions {
    /// Returns true if these permissions describe a
    /// readonly (unwritable) file.
    pub fn readonly(&self) -> bool {
        self.read_only
    }

    /// Modifies the readonly flag for this set of permissions.
    pub fn set_readonly(&mut self, readonly: bool) {
        self.read_only = readonly;
    }
}

/// Access times for in-memory files.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Copy, Clone)]
pub(crate) struct FileTime {
    /// Time created.
    created: SystemTime,
    /// Time last accessed.
    accessed: SystemTime,
    /// Time last modified.
    modified: SystemTime,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Default for FileTime {
    fn default() -> Self {
        Self {
            created: SystemTime::now(),
            accessed: SystemTime::now(),
            modified: SystemTime::now(),
        }
    }
}

/// A structure representing a type of file with accessors
/// for each file type.
#[derive(Debug, Copy, Clone)]
pub struct FileType(FileFlags);

impl FileType {
    /// Tests whether this file type represents a directory.
    pub fn is_dir(&self) -> bool {
        self.0.contains(FileFlags::DIR)
    }

    /// Tests whether this file type represents a regular file.
    pub fn is_file(&self) -> bool {
        self.0.contains(FileFlags::FILE)
    }

    /// Tests whether this file type represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.0.contains(FileFlags::SYM_LINK)
    }
}

/// Metadata information about a file.
#[derive(Debug, Clone)]
pub struct Metadata {
    permissions: Permissions,
    flags: FileFlags,
    length: u64,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
}

impl Metadata {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    /// Create new meta data for a file.
    pub(crate) fn new(
        permissions: Permissions,
        flags: FileFlags,
        length: u64,
        time: FileTime,
    ) -> Self {
        Self {
            permissions,
            flags,
            length,
            time,
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    /// Create new meta data for a file.
    pub(crate) fn new(
        permissions: Permissions,
        flags: FileFlags,
        length: u64,
    ) -> Self {
        Self {
            permissions,
            flags,
            length,
        }
    }

    /// Returns the file type for this metadata.
    pub fn file_type(&self) -> FileType {
        FileType(self.flags)
    }

    /// Tests whether this file type represents a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    /// Tests whether this file type represents a regular file.
    pub fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    /// Tests whether this file type represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type().is_symlink()
    }

    /// Returns the size of the file, in bytes, this metadata is for.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Returns the permissions of the file this metadata is for.
    pub fn permissions(&self) -> Permissions {
        self.permissions
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    /// Returns the last access time of this metadata.
    pub fn accessed(&self) -> io::Result<SystemTime> {
        Ok(self.time.accessed)
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    /// Returns the creation time listed in this metadata.
    pub fn created(&self) -> io::Result<SystemTime> {
        Ok(self.time.created)
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    /// Returns the last modification time listed in this metadata.
    pub fn modified(&self) -> io::Result<SystemTime> {
        Ok(self.time.modified)
    }
}
