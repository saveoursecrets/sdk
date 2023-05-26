//! File system backed by memory.
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

/// Result type for the in-memory file system.
pub type Result<T> = std::result::Result<T, Error>;

type FileSystem = BTreeMap<PathBuf, Arc<RwLock<MemoryFd>>>;

// File system contents.
static mut FILE_SYSTEM: Lazy<FileSystem> = Lazy::new(|| BTreeMap::new());

// Lock for when we need to modify the file system by adding
// or removing paths.
static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Directory reference.
#[derive(Default)]
pub(crate) struct MemoryDir;

/// File content.
#[derive(Default, Debug)]
pub(crate) struct MemoryFile {
    pub(crate) contents: Vec<u8>,
}

impl MemoryFile {
    /// Determine if the file is empty.
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Get the length of the file buffer.
    pub fn len(&self) -> usize {
        self.contents.len()
    }
}

/// File descriptor.
pub(crate) enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

mod file;
mod open_options;
pub use file::File;
pub use open_options::OpenOptions;

/*
/// Ensure a path exists.
async fn ensure_exists(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fd = FILE_SYSTEM.get(path.as_ref());
        if fd.is_none() {
            return Err(ErrorKind::NotFound.into());
        }
    }
    Ok(())
}
*/

/// Ensure a path is a file and exists.
async fn ensure_file(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fd = FILE_SYSTEM.get(path.as_ref());
        if let Some(fd) = fd {
            let fd = fd.read().await;
            let is_file = matches!(&*fd, MemoryFd::File(_));
            if !is_file {
                return Err(ErrorKind::PermissionDenied.into());
            }
        } else {
            return Err(ErrorKind::NotFound.into());
        }
    }
    Ok(())
}

/// Ensure a path is a directory and exists.
async fn ensure_dir(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fd = FILE_SYSTEM.get(path.as_ref());
        if let Some(fd) = fd {
            let fd = fd.read().await;
            let is_file = matches!(&*fd, MemoryFd::Dir(_));
            if !is_file {
                return Err(ErrorKind::PermissionDenied.into());
            }
        } else {
            return Err(ErrorKind::NotFound.into());
        }
    }
    Ok(())
}

/// Find all the descendants of a path.
async fn find_descendants(
    fs: &FileSystem,
    path: impl AsRef<Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for (target, file) in fs.iter() {
        if target.starts_with(path.as_ref()) && target != path.as_ref() {
            paths.push(target.clone());
        }
    }
    paths
}

/// Determine if a path is a file.
async fn is_file(fs: &FileSystem, path: impl AsRef<Path>) -> bool {
    if let Some(fd) = fs.get(path.as_ref()) {
        let fd = fd.read().await;
        matches!(&*fd, MemoryFd::File(_))
    } else {
        false
    }
}

/// Creates a future that will open a file for writing
/// and write the entire contents to it.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(parent) = path.parent() {
            if let Some(parent) = fs.get(parent) {
                let fd = parent.read().await;
                let is_dir = matches!(&*fd, MemoryFd::Dir(_));
                if !is_dir {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            }
        }
        let fd = fs.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::File(Default::default())))
        });
        let mut fd = fd.write().await;
        if let MemoryFd::File(fd) = &mut *fd {
            fd.contents = contents.as_ref().to_vec();
        }
    }
    Ok(())
}

/// Reads the entire contents of a file into a bytes vector.
pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    unsafe {
        if let Some(fd) = FILE_SYSTEM.get(path.as_ref()) {
            let fd = fd.read().await;
            if let MemoryFd::File(fd) = &*fd {
                Ok(fd.contents.clone())
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    ensure_file(path.as_ref()).await?;

    let _ = FS_LOCK.lock().await;
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        fs.remove(path.as_ref());
    }
    Ok(())
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    ensure_dir(path.as_ref()).await?;

    // FIXME: ensure directory is empty

    let _ = FS_LOCK.lock().await;
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        fs.remove(path.as_ref());
    }

    Ok(())
}

/// Removes a directory at this path, after removing
/// all its contents. Use carefully!
pub async fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        if let Some(fd) = FILE_SYSTEM.get(path.as_ref()) {
            let fd = fd.read().await;
            let is_dir = matches!(&*fd, MemoryFd::Dir(_));
            if is_dir {
                let descendants =
                    find_descendants(&*FILE_SYSTEM, path.as_ref()).await;
                for child in descendants {
                    if is_file(&*FILE_SYSTEM, &child).await {
                        remove_file(&child).await?;
                    } else {
                        remove_dir(&child).await?;
                    }
                }
                Ok(())
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Renames a file or directory to a new name, replacing
/// the original file if to already exists.
pub async fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = fs.remove(from.as_ref()) {
            fs.insert(to.as_ref().to_path_buf(), fd);
            Ok(())
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Creates a new, empty directory at the provided path.
pub async fn create_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let path = path.as_ref().to_path_buf();
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();

        if let Some(parent) = path.parent() {
            if let Some(parent) = fs.get(parent) {
                let parent = parent.read().await;
                let is_dir = matches!(&*parent, MemoryFd::Dir(_));
                if !is_dir {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            }
        }
        fs.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::Dir(Default::default())))
        });
    }
    Ok(())
}

/// Recursively creates a directory and all of its parent
/// components if they are missing.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;
    let path = path.as_ref().to_path_buf();

    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        // FIXME: ensure all parents do not exist
        // FIXME: or that all parents are directories
        fs.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::Dir(Default::default())))
        });
    }

    Ok(())
}

/// Creates a future which will open a file for reading
/// and read the entire contents into a string and return said string.
pub async fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
    let contents = read(path).await?;
    Ok(String::from_utf8(contents).map_err(|_| {
        let err: Error = ErrorKind::InvalidData.into();
        err
    })?)
}

/*
/// Returns a stream over the entries within a directory.
pub async fn read_dir(path: impl AsRef<Path>) -> Result<ReadDir> {
    todo!();
}
*/
