use self::State::*;
use futures::ready;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, RwLock};
use tokio::{runtime::Handle, task::JoinHandle};

use std::fmt;
use std::fs::Permissions;
use std::future::Future;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Poll::*;

use super::{MemoryFd, Metadata, OpenOptions, PathBuf, FILE_SYSTEM};

pub(crate) fn spawn_blocking<F, R>(func: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let rt = Handle::current();
    rt.spawn_blocking(func)
}

type Buf = Arc<RwLock<MemoryFd>>;

/// A reference to an open file on the filesystem.
pub struct File {
    inner: Mutex<Inner>,
}

impl From<(Arc<RwLock<MemoryFd>>, usize)> for File {
    fn from(value: (Arc<RwLock<MemoryFd>>, usize)) -> Self {
        let (file, length) = value;
        Self {
            inner: Mutex::new(Inner {
                state: State::Idle(Some(file)),
                pos: 0,
                length,
                last_write_err: None,
            }),
        }
    }
}

struct Inner {
    state: State,
    /// Errors from writes/flushes are returned in
    /// write/flush calls. If a write error is observed
    /// while performing a read, it is saved until the next
    /// write / flush call.
    last_write_err: Option<io::ErrorKind>,
    length: usize,
    pos: u64,
}

#[derive(Debug)]
pub(super) enum State {
    Idle(Option<Buf>),
    Busy(JoinHandle<(Operation, Buf)>),
}

#[derive(Debug)]
pub(super) enum Operation {
    Read(io::Result<usize>),
    Write(io::Result<()>),
    Seek(io::Result<u64>),
}

impl File {
    /// Attempts to open a file in read-only mode.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<File> {
        Ok(OpenOptions::new().read(true).open(path).await?)
    }

    /// Opens a file in write-only mode.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await?)
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub async fn sync_all(&self) -> io::Result<()> {
        Ok(())
    }

    /// This function is similar to `sync_all`, except that it may not
    /// synchronize file metadata to the filesystem.
    pub async fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    /// Truncates or extends the underlying file, updating
    /// the size of this file to become size.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.complete_inflight().await;

        let mut buf = match inner.state {
            Idle(ref mut buf_cell) => buf_cell.take().unwrap(),
            _ => unreachable!(),
        };

        let mut writer = buf.write().await;

        if size < writer.len() as u64 {
            match &mut *writer {
                MemoryFd::File(file) => {
                    file.contents.truncate(size as usize);
                }
                _ => unreachable!(),
            }
            if inner.pos > size {
                inner.pos = size;
            }
        } else if size > writer.len() as u64 {
            let amount = writer.len() as u64 - size;
            let elements = vec![0; amount as usize];

            match &mut *writer {
                MemoryFd::File(file) => {
                    file.contents.extend(elements.iter());
                }
                _ => unreachable!(),
            }
        }

        drop(writer);

        inner.state = Idle(Some(buf));

        Ok(())
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        let mut inner = self.inner.lock().await;
        inner.complete_inflight().await;

        let mut buf = match inner.state {
            Idle(ref mut buf_cell) => buf_cell.take().unwrap(),
            _ => unreachable!(),
        };

        let reader = buf.read().await;
        let meta_data = reader.metadata();
        drop(reader);
        inner.state = Idle(Some(buf));
        Ok(meta_data)
    }

    /// Creates a new `File` instance that shares the same underlying file handle
    /// as the existing `File` instance. Reads, writes, and seeks will affect both
    /// File instances simultaneously.
    pub async fn try_clone(&self) -> io::Result<File> {
        unimplemented!();
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        unimplemented!();
    }
}

impl AsyncRead for File {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let inner = me.inner.get_mut();

        todo!();

        /*
        loop {
            match inner.state {
                Idle(ref mut buf_cell) => {
                    let mut buf = buf_cell.take().unwrap();

                    if !buf.is_empty() {
                        buf.copy_to(dst);
                        *buf_cell = Some(buf);
                        return Ready(Ok(()));
                    }

                    buf.ensure_capacity_for(dst);
                    let std = me.std.clone();

                    inner.state = Busy(spawn_blocking(move || {
                        let res = buf.read_from(&mut &*std);
                        (Operation::Read(res), buf)
                    }));
                }
                Busy(ref mut rx) => {
                    let (op, mut buf) = ready!(Pin::new(rx).poll(cx))?;

                    match op {
                        Operation::Read(Ok(_)) => {
                            buf.copy_to(dst);
                            inner.state = Idle(Some(buf));
                            return Ready(Ok(()));
                        }
                        Operation::Read(Err(e)) => {
                            assert!(buf.is_empty());

                            inner.state = Idle(Some(buf));
                            return Ready(Err(e));
                        }
                        Operation::Write(Ok(_)) => {
                            assert!(buf.is_empty());
                            inner.state = Idle(Some(buf));
                            continue;
                        }
                        Operation::Write(Err(e)) => {
                            assert!(inner.last_write_err.is_none());
                            inner.last_write_err = Some(e.kind());
                            inner.state = Idle(Some(buf));
                        }
                        Operation::Seek(result) => {
                            assert!(buf.is_empty());
                            inner.state = Idle(Some(buf));
                            if let Ok(pos) = result {
                                inner.pos = pos;
                            }
                            continue;
                        }
                    }
                }
            }
        }
        */
    }
}

impl AsyncSeek for File {
    fn start_seek(self: Pin<&mut Self>, pos: SeekFrom) -> io::Result<()> {
        let me = self.get_mut();
        let inner = me.inner.get_mut();
        let length = inner.length;

        match inner.state {
            Busy(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "other file operation is pending, call poll_complete before start_seek",
            )),
            Idle(ref mut buf_cell) => {
                let pos = match pos {
                    SeekFrom::Start(pos) => pos,
                    SeekFrom::End(pos) => {
                        if pos as usize <= length {
                            (length - pos as usize) as u64
                        } else {
                            0u64
                        }
                    },
                    SeekFrom::Current(pos) => {
                        if pos < 0 {
                            inner.pos - pos as u64
                        } else {
                            inner.pos + pos as u64
                        }
                    },
                };
                inner.pos = pos;
                Ok(())
            }
        }
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>> {
        let inner = self.inner.get_mut();

        loop {
            match inner.state {
                Idle(_) => return Poll::Ready(Ok(inner.pos)),
                Busy(ref mut rx) => {
                    let (op, buf) = ready!(Pin::new(rx).poll(cx))?;
                    inner.state = Idle(Some(buf));

                    match op {
                        Operation::Read(_) => {}
                        Operation::Write(Err(e)) => {
                            assert!(inner.last_write_err.is_none());
                            inner.last_write_err = Some(e.kind());
                        }
                        Operation::Write(_) => {}
                        Operation::Seek(res) => {
                            if let Ok(pos) = res {
                                inner.pos = pos;
                            }
                            return Ready(res);
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for File {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        todo!();

        /*
        ready!(crate::trace::trace_leaf(cx));
        let me = self.get_mut();
        let inner = me.inner.get_mut();

        if let Some(e) = inner.last_write_err.take() {
            return Ready(Err(e.into()));
        }

        loop {
            match inner.state {
                Idle(ref mut buf_cell) => {
                    let mut buf = buf_cell.take().unwrap();

                    let seek = if !buf.is_empty() {
                        Some(SeekFrom::Current(buf.discard_read()))
                    } else {
                        None
                    };

                    let n = buf.copy_from(src);
                    let std = me.std.clone();

                    let blocking_task_join_handle = spawn_mandatory_blocking(move || {
                        let res = if let Some(seek) = seek {
                            (&*std).seek(seek).and_then(|_| buf.write_to(&mut &*std))
                        } else {
                            buf.write_to(&mut &*std)
                        };

                        (Operation::Write(res), buf)
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Other, "background task failed")
                    })?;

                    inner.state = Busy(blocking_task_join_handle);

                    return Ready(Ok(n));
                }
                Busy(ref mut rx) => {
                    let (op, buf) = ready!(Pin::new(rx).poll(cx))?;
                    inner.state = Idle(Some(buf));

                    match op {
                        Operation::Read(_) => {
                            // We don't care about the result here. The fact
                            // that the cursor has advanced will be reflected in
                            // the next iteration of the loop
                            continue;
                        }
                        Operation::Write(res) => {
                            // If the previous write was successful, continue.
                            // Otherwise, error.
                            res?;
                            continue;
                        }
                        Operation::Seek(_) => {
                            // Ignore the seek
                            continue;
                        }
                    }
                }
            }
        }
        */
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let inner = self.inner.get_mut();
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.poll_flush(cx)
    }
}

impl fmt::Debug for File {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("vfs::memory::File").finish()
    }
}

impl Inner {
    async fn complete_inflight(&mut self) {
        use std::future::poll_fn;
        poll_fn(|cx| self.poll_complete_inflight(cx)).await
    }

    fn poll_complete_inflight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self.poll_flush(cx) {
            Poll::Ready(Err(e)) => {
                self.last_write_err = Some(e.kind());
                Poll::Ready(())
            }
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let Some(e) = self.last_write_err.take() {
            return Ready(Err(e.into()));
        }

        let (op, buf) = match self.state {
            Idle(_) => return Ready(Ok(())),
            Busy(ref mut rx) => ready!(Pin::new(rx).poll(cx))?,
        };

        // The buffer is not used here
        self.state = Idle(Some(buf));

        match op {
            Operation::Read(_) => Ready(Ok(())),
            Operation::Write(res) => Ready(res),
            Operation::Seek(_) => Ready(Ok(())),
        }
    }
}
