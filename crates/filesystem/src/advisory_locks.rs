use async_fd_lock::LockWrite;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

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
    let mut guard = file.lock_write().await.map_err(|e| e.error)?;
    guard.write_all(buf.as_ref()).await?;
    guard.flush().await?;
    Ok(())
}
