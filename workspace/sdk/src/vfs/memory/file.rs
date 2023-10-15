//! In-memory file modified from the `tokio::fs::File`
//! implementation to write to a Cursor.
//!
//! All credit to the tokio authors.
//!
use self::State::*;
use futures::ready;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::{runtime::Handle, task::JoinHandle};

use std::cmp;
use std::fmt;
use std::future::Future;
use std::io::{self, prelude::*, ErrorKind, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::Poll::*;

use super::{
    fs::{Fd, FileContent, MemoryFd},
    metadata,
    open_options::OpenFlags,
    Metadata, OpenOptions, Permissions,
};

pub(crate) fn spawn_blocking<F, R>(func: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let rt = Handle::current();
    rt.spawn_blocking(func)
}

/// A reference to an open file on the filesystem.
pub struct File {
    std: FileContent,
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl File {
    pub(super) async fn new(fd: Fd, flags: OpenFlags) -> io::Result<Self> {
        let (std, path) = {
            let fd = fd.read().await;
            let path = fd.path().await;
            match &*fd {
                MemoryFd::File(fd) => (fd.contents(), path),
                _ => return Err(ErrorKind::PermissionDenied.into()),
            }
        };

        // Must reset the cursor every time we open a file
        if flags.contains(OpenFlags::APPEND) {
            // Reset seek position to the end for append mode
            let mut data = std.lock();
            let len = data.get_ref().len();
            data.set_position(len as u64);
        } else {
            // Reset seek position to the beginning
            let mut data = std.lock();
            data.set_position(0);
        }

        Ok(Self {
            std,
            path,
            inner: Mutex::new(Inner {
                state: State::Idle(Some(Buf {
                    buf: Vec::new(),
                    pos: 0,
                })),
                pos: 0,
                last_write_err: None,
            }),
        })
    }
}

struct Inner {
    state: State,
    /// Errors from writes/flushes are returned in
    /// write/flush calls. If a write error is observed
    /// while performing a read, it is saved until the next
    /// write / flush call.
    last_write_err: Option<io::ErrorKind>,
    pos: u64,
}

#[derive(Debug)]
enum State {
    Idle(Option<Buf>),
    Busy(JoinHandle<(Operation, Buf)>),
}

#[derive(Debug)]
enum Operation {
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
    ///
    /// If the size is less than the current file's size,
    /// then the file will be shrunk. If it is greater
    /// than the current file's size, then the file
    /// will be extended to size and have all of the
    /// intermediate data filled in with 0s.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file
    /// is not opened for writing.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.complete_inflight().await;

        let mut buf = match inner.state {
            Idle(ref mut buf_cell) => buf_cell.take().unwrap(),
            _ => unreachable!(),
        };

        let seek = if !buf.is_empty() {
            Some(SeekFrom::Current(buf.discard_read()))
        } else {
            None
        };

        let std = self.std.clone();

        inner.state = Busy(spawn_blocking(move || {
            let mut std = std.lock();
            let len = std.get_ref().len() as u64;

            let extension = if size <= len {
                None
            } else {
                let amount = size - len;
                let elements = vec![0; amount as usize];
                Some(elements)
            };

            let res = if let Some(seek) = seek {
                std.seek(seek).and_then(|_| {
                    if let Some(zero) = extension {
                        std.get_mut().extend(zero.iter());
                    } else {
                        std.get_mut().truncate(size as usize);
                    }
                    Ok(())
                })
            } else {
                if let Some(zero) = extension {
                    std.get_mut().extend(zero.iter());
                } else {
                    std.get_mut().truncate(size as usize);
                }
                Ok(())
            }
            .map(|_| 0); // the value is discarded later

            // Return the result as a seek
            (Operation::Seek(res), buf)
        }));

        let (op, buf) = match inner.state {
            Idle(_) => unreachable!(),
            Busy(ref mut rx) => rx.await?,
        };

        inner.state = Idle(Some(buf));

        match op {
            Operation::Seek(res) => res.map(|pos| {
                inner.pos = pos;
            }),
            _ => unreachable!(),
        }
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        metadata(&self.path).await
    }

    /// Creates a new `File` instance that shares the same
    /// underlying file handle as the existing `File`
    /// instance. Reads, writes, and seeks will affect both
    /// File instances simultaneously.
    pub async fn try_clone(&self) -> io::Result<File> {
        unimplemented!();
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(
        &self,
        _perm: Permissions,
    ) -> io::Result<()> {
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
                        let mut std = std.lock();
                        let res = buf.read_from(&mut *std);
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
    }
}

impl AsyncSeek for File {
    fn start_seek(self: Pin<&mut Self>, mut pos: SeekFrom) -> io::Result<()> {
        let me = self.get_mut();
        let inner = me.inner.get_mut();

        match inner.state {
            Busy(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "other file operation is pending, call poll_complete before start_seek",
            )),
            Idle(ref mut buf_cell) => {
                let mut buf = buf_cell.take().unwrap();

                // Factor in any unread data from the buf
                if !buf.is_empty() {
                    let n = buf.discard_read();

                    if let SeekFrom::Current(ref mut offset) = pos {
                        *offset += n;
                    }
                }

                let std = me.std.clone();

                inner.state = Busy(spawn_blocking(move || {
                    let mut std = std.lock();
                    let res = std.seek(pos);
                    (Operation::Seek(res), buf)
                }));
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

                    let blocking_task_join_handle =
                        spawn_blocking(move || {
                            let mut std = std.lock();

                            let res = if let Some(seek) = seek {
                                std.seek(seek)
                                    .and_then(|_| buf.write_to(&mut *std))
                            } else {
                                buf.write_to(&mut *std)
                            };

                            (Operation::Write(res), buf)
                        });

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

macro_rules! uninterruptibly {
    ($e:expr) => {{
        loop {
            match $e {
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                res => break res,
            }
        }
    }};
}

#[derive(Debug)]
struct Buf {
    buf: Vec<u8>,
    pos: usize,
}

pub(crate) const MAX_BUF: usize = 2 * 1024 * 1024;

impl Buf {
    /*
    pub(crate) fn with_capacity(n: usize) -> Buf {
        Buf {
            buf: Vec::with_capacity(n),
            pos: 0,
        }
    }
    */

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn copy_to(&mut self, dst: &mut ReadBuf<'_>) -> usize {
        let n = cmp::min(self.len(), dst.remaining());
        dst.put_slice(&self.bytes()[..n]);
        self.pos += n;

        if self.pos == self.buf.len() {
            self.buf.truncate(0);
            self.pos = 0;
        }

        n
    }

    pub(crate) fn copy_from(&mut self, src: &[u8]) -> usize {
        assert!(self.is_empty());

        let n = cmp::min(src.len(), MAX_BUF);

        self.buf.extend_from_slice(&src[..n]);
        n
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub(crate) fn ensure_capacity_for(&mut self, bytes: &ReadBuf<'_>) {
        assert!(self.is_empty());

        let len = cmp::min(bytes.remaining(), MAX_BUF);

        if self.buf.len() < len {
            self.buf.reserve(len - self.buf.len());
        }

        unsafe {
            self.buf.set_len(len);
        }
    }

    pub(crate) fn read_from<T: Read>(
        &mut self,
        rd: &mut T,
    ) -> io::Result<usize> {
        let res = uninterruptibly!(rd.read(&mut self.buf));

        if let Ok(n) = res {
            self.buf.truncate(n);
        } else {
            self.buf.clear();
        }

        assert_eq!(self.pos, 0);

        res
    }

    pub(crate) fn write_to<T: Write>(
        &mut self,
        wr: &mut T,
    ) -> io::Result<()> {
        assert_eq!(self.pos, 0);

        // `write_all` already ignores interrupts
        let res = wr.write_all(&self.buf);
        self.buf.clear();
        res
    }

    pub(crate) fn discard_read(&mut self) -> i64 {
        let ret = -(self.bytes().len() as i64);
        self.pos = 0;
        self.buf.truncate(0);
        ret
    }
}
