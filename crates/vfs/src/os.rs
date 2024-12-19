//! Native operating system file system.
pub use tokio::fs::*;

use async_fd_lock::{LockRead, LockWrite, RwLockWriteGuard};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Write a file acquiring an exclusive lock.
///
/// The file is created if it does not exist and
/// truncated if it does exist.
pub async fn write_exclusive(
    path: impl AsRef<Path>,
    buf: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path.as_ref())
        .await?;
    let mut guard = lock_write(file).await?;
    guard.write_all(buf.as_ref()).await?;
    guard.flush().await?;
    Ok(())
}

/// Acquire an exclusive write lock.
pub async fn lock_write(
    file: File,
) -> std::io::Result<RwLockWriteGuard<File>> {
    Ok(file.lock_write().await?)
}

/// Read acquiring an exclusive lock.
pub async fn read_exclusive(
    path: impl AsRef<Path>,
) -> std::io::Result<Vec<u8>> {
    let mut guard = File::open(path.as_ref()).await?.lock_write().await?;
    let mut out = Vec::new();
    guard.read_to_end(&mut out).await?;
    Ok(out)
}

/// Read acquiring a shared read lock.
pub async fn read_shared(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut guard = File::open(path.as_ref()).await?.lock_read().await?;
    let mut out = Vec::new();
    guard.read_to_end(&mut out).await?;
    Ok(out)
}
