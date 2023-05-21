//! File system backed by memory.
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};
use tokio::sync::RwLock;

/// Result type for the in-memory file system.
pub type Result<T> = std::result::Result<T, Error>;

// Simple file system - does not support multiple concurrent writes.
static FILE_SYSTEM: Lazy<RwLock<HashMap<PathBuf, MemoryFd>>> =
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
            todo!("check parent is directory");
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
