//! Advisory file locks.
use {
    file_guard::{try_lock, FileGuard, Lock},
    std::{
        fs::{File, OpenOptions},
        future::Future,
        io::ErrorKind,
        path::Path,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    },
};

/// Advisory file lock.
#[allow(dead_code)]
pub struct FileLock {
    file: Arc<File>,
    guard: FileGuard<Arc<File>>,
}

impl FileLock {
    /// Lock a file for exclusive access.
    pub fn lock_exclusive(
        path: impl AsRef<Path>,
    ) -> impl Future<Output = std::io::Result<FileGuard<Arc<File>>>> {
        Box::pin(async move {
            let file = Arc::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path.as_ref())?,
            );
            let fut = LockFuture {
                file,
                lock: Lock::Exclusive,
            };
            fut.await
        })
    }
}

/// Future to try to acquire a lock.
pub struct LockFuture {
    file: Arc<File>,
    lock: Lock,
}

impl Future for LockFuture {
    type Output = std::io::Result<FileGuard<Arc<File>>>;

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match try_lock(self.file.clone(), self.lock, 0, 1) {
            Ok(lock) => Poll::Ready(Ok(lock)),
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(e)),
            },
        }
    }
}
