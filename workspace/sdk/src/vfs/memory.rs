//! File system backed by memory.
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    ops::Deref,
    path::{Path, PathBuf},
};
use tokio::sync::RwLock;

/// Result type for the in-memory file system.
pub type Result<T> = std::result::Result<T, Error>;

type FileSystem = HashMap<PathBuf, MemoryFd>;

// Simple file system - does not support multiple concurrent writes.
static FILE_SYSTEM: Lazy<RwLock<FileSystem>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Directory reference.
#[derive(Default)]
pub struct MemoryDir;

/// File content.
#[derive(Default)]
pub struct MemoryFile {
    contents: Vec<u8>,
}

/// File descriptor.
pub enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

// NOTE: temporary export to keep the compiler happy
pub use tokio::fs::File;

/// Find all the descendants of a path.
async fn find_descendants(
    fs: &FileSystem,
    path: impl AsRef<Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    //let fs = FILE_SYSTEM.read().await;
    for (target, file) in fs.iter() {
        if target.starts_with(path.as_ref()) && target != path.as_ref() {
            paths.push(target.clone());
        }
    }
    paths
}

/// Determine if a path is a file.
pub async fn is_file(fs: &FileSystem, path: impl AsRef<Path>) -> bool {
    fs.get(path.as_ref())
        .map(|fd| matches!(fd, MemoryFd::File(_)))
        .unwrap_or_default()
}

/// Creates a future that will open a file for writing
/// and write the entire contents to it.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    let mut fs = FILE_SYSTEM.write().await;
    if let Some(parent) = path.parent() {
        if let Some(parent) = fs.get(parent) {
            let is_dir = matches!(parent, MemoryFd::Dir(_));
            if !is_dir {
                return Err(ErrorKind::PermissionDenied.into());
            }
        }
    }
    let fd = fs
        .entry(path)
        .or_insert_with(|| MemoryFd::File(Default::default()));
    if let MemoryFd::File(fd) = fd {
        fd.contents = contents.as_ref().to_vec();
    }
    Ok(())
}

/// Reads the entire contents of a file into a bytes vector.
pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let fs = FILE_SYSTEM.read().await;
    if let Some(fd) = fs.get(path.as_ref()) {
        if let MemoryFd::File(fd) = fd {
            Ok(fd.contents.clone())
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    let mut fs = FILE_SYSTEM.write().await;
    let fd = fs
        .get(path.as_ref())
        .map(|fd| matches!(fd, MemoryFd::File(_)));
    if let Some(is_file) = fd {
        if is_file {
            fs.remove(path.as_ref());
            Ok(())
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    let mut fs = FILE_SYSTEM.write().await;
    let fd = fs
        .get(path.as_ref())
        .map(|fd| matches!(fd, MemoryFd::Dir(_)));
    if let Some(is_dir) = fd {
        if is_dir {
            fs.remove(path.as_ref());
            Ok(())
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Removes a directory at this path, after removing
/// all its contents. Use carefully!
pub async fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let fs = FILE_SYSTEM.read().await;
    let fd = fs
        .get(path.as_ref())
        .map(|fd| matches!(fd, MemoryFd::Dir(_)));
    if let Some(is_dir) = fd {
        if is_dir {
            let descendants =
                find_descendants(fs.deref(), path.as_ref()).await;
            for child in descendants {
                if is_file(fs.deref(), &child).await {
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

/// Renames a file or directory to a new name, replacing
/// the original file if to already exists.
pub async fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<()> {
    let mut fs = FILE_SYSTEM.write().await;
    if let Some(fd) = fs.remove(from.as_ref()) {
        fs.insert(to.as_ref().to_path_buf(), fd);
        Ok(())
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Creates a new, empty directory at the provided path.
pub async fn create_dir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    let mut fs = FILE_SYSTEM.write().await;
    if let Some(parent) = path.parent() {
        if let Some(parent) = fs.get(parent) {
            let is_dir = matches!(parent, MemoryFd::Dir(_));
            if !is_dir {
                return Err(ErrorKind::PermissionDenied.into());
            }
        }
    }
    let fd = fs
        .entry(path)
        .or_insert_with(|| MemoryFd::Dir(Default::default()));
    Ok(())
}

/// Recursively creates a directory and all of its parent
/// components if they are missing.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    let mut fs = FILE_SYSTEM.write().await;
    let fd = fs
        .entry(path)
        .or_insert_with(|| MemoryFd::Dir(Default::default()));
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
