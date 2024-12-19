//! Advisory file lock functions exported for desktop platforms.
#[cfg(all(
    not(test),
    not(all(target_arch = "wasm32", target_os = "unknown")),
    not(feature = "mem-fs"),
    not(target_os = "ios"),
    not(target_os = "android"),
))]
mod sys {
    use async_fd_lock::{LockWrite, RwLockWriteGuard};
    use std::path::Path;
    use tokio::fs::{File, OpenOptions};
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
}

#[cfg(all(
    not(test),
    not(all(target_arch = "wasm32", target_os = "unknown")),
    not(feature = "mem-fs"),
    not(target_os = "ios"),
    not(target_os = "android"),
))]
pub use sys::*;

#[cfg(any(
    feature = "mem-fs",
    all(target_arch = "wasm32", target_os = "unknown"),
    target_os = "ios",
    target_os = "android",
))]
mod noop {
    use crate::{read, write, File};
    use std::path::Path;

    /// Write acquiring an exclusive lock.
    ///
    /// Currently a NOOP for the in-memory implementation.
    pub async fn write_exclusive(
        path: impl AsRef<Path>,
        buf: impl AsRef<[u8]>,
    ) -> std::io::Result<()> {
        write(path, buf).await
    }

    /// Acquire an exclusive write lock.
    pub async fn lock_write(file: File) -> std::io::Result<File> {
        Ok(file)
    }

    /// Read acquiring an exclusive lock.
    ///
    /// Currently a NOOP for the in-memory implementation.
    pub async fn read_exclusive(
        path: impl AsRef<Path>,
    ) -> std::io::Result<Vec<u8>> {
        read(path).await
    }
}

#[cfg(any(
    feature = "mem-fs",
    all(target_arch = "wasm32", target_os = "unknown"),
    target_os = "ios",
    target_os = "android",
))]
pub use noop::*;
