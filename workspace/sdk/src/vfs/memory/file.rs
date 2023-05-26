//! Types for working with [`File`].
//!
//! [`File`]: File

use self::State::*;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use std::fmt;
use std::fs::{Metadata, Permissions};
use std::future::Future;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Poll::*;

use super::OpenOptions;

/// A reference to an open file on the filesystem.
pub struct File {
    //options: OpenOptions,
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,

    /// Errors from writes/flushes are returned in write/flush calls. If a write
    /// error is observed while performing a read, it is saved until the next
    /// write / flush call.
    last_write_err: Option<io::ErrorKind>,

    pos: u64,
}

#[derive(Debug)]
enum State {

    /*
    Idle(Option<Buf>),
    Busy(JoinHandle<(Operation, Buf)>),
    */
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
        let path = path.as_ref().to_owned();

        /*
        let std = asyncify(|| StdFile::open(path)).await?;

        Ok(File::from_std(std))
        */

        todo!();
    }

    /// Opens a file in write-only mode.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<File> {
        let path = path.as_ref().to_owned();
        /*
        let std_file = asyncify(move || StdFile::create(path)).await?;
        Ok(File::from_std(std_file))
        */
        todo!();
    }

    /// Attempts to sync all OS-internal metadata to disk.
    pub async fn sync_all(&self) -> io::Result<()> {

        /*
        let mut inner = self.inner.lock().await;
        inner.complete_inflight().await;

        let std = self.std.clone();
        asyncify(move || std.sync_all()).await
        */

        todo!();
    }

    /// This function is similar to `sync_all`, except that it may not
    /// synchronize file metadata to the filesystem.
    pub async fn sync_data(&self) -> io::Result<()> {

        /*
        let mut inner = self.inner.lock().await;
        inner.complete_inflight().await;

        let std = self.std.clone();
        asyncify(move || std.sync_data()).await
        */

        todo!();
    }

    /// Truncates or extends the underlying file, updating the size of this file to become size.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {

        todo!();

        /*
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
            let res = if let Some(seek) = seek {
                (&*std).seek(seek).and_then(|_| std.set_len(size))
            } else {
                std.set_len(size)
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
        */
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        todo!();
        /*
        let std = self.std.clone();
        asyncify(move || std.metadata()).await
        */
    }

    /// Creates a new `File` instance that shares the same underlying file handle
    /// as the existing `File` instance. Reads, writes, and seeks will affect both
    /// File instances simultaneously.
    pub async fn try_clone(&self) -> io::Result<File> {

        /*
        let std = self.std.clone();
        let std_file = asyncify(move || std.try_clone()).await?;
        Ok(File::from_std(std_file))
        */

        todo!();
    }

    /// Changes the permissions on the underlying file.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        /*
        let std = self.std.clone();
        asyncify(move || std.set_permissions(perm)).await
        */

        todo!();
    }
}

impl AsyncRead for File {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {

        /*
        ready!(crate::trace::trace_leaf(cx));
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
        todo!();
    }
}

impl AsyncSeek for File {
    fn start_seek(self: Pin<&mut Self>, mut pos: SeekFrom) -> io::Result<()> {
        todo!();
        /*
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
                    let res = (&*std).seek(pos);
                    (Operation::Seek(res), buf)
                }));
                Ok(())
            }
        }
        */
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {

        todo!();

        /*
        ready!(crate::trace::trace_leaf(cx));
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
        */
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {

        todo!();

        /*
        ready!(crate::trace::trace_leaf(cx));
        let inner = self.inner.get_mut();
        inner.poll_flush(cx)
        */
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        todo!();

        /*
        ready!(crate::trace::trace_leaf(cx));
        self.poll_flush(cx)
        */
    }
}

/*
impl fmt::Debug for File {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("tokio::fs::File")
            .field("std", &self.std)
            .finish()
    }
}
*/

/*
#[cfg(unix)]
impl std::os::unix::io::AsRawFd for File {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.std.as_raw_fd()
    }
}

#[cfg(all(unix, not(tokio_no_as_fd)))]
impl std::os::unix::io::AsFd for File {
    fn as_fd(&self) -> std::os::unix::io::BorrowedFd<'_> {
        unsafe {
            std::os::unix::io::BorrowedFd::borrow_raw(std::os::unix::io::AsRawFd::as_raw_fd(self))
        }
    }
}

#[cfg(unix)]
impl std::os::unix::io::FromRawFd for File {
    unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> Self {
        StdFile::from_raw_fd(fd).into()
    }
}

cfg_windows! {
    use crate::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    #[cfg(not(tokio_no_as_fd))]
    use crate::os::windows::io::{AsHandle, BorrowedHandle};

    impl AsRawHandle for File {
        fn as_raw_handle(&self) -> RawHandle {
            self.std.as_raw_handle()
        }
    }

    #[cfg(not(tokio_no_as_fd))]
    impl AsHandle for File {
        fn as_handle(&self) -> BorrowedHandle<'_> {
            unsafe {
                BorrowedHandle::borrow_raw(
                    AsRawHandle::as_raw_handle(self),
                )
            }
        }
    }

    impl FromRawHandle for File {
        unsafe fn from_raw_handle(handle: RawHandle) -> Self {
            StdFile::from_raw_handle(handle).into()
        }
    }
}
*/

impl Inner {
    async fn complete_inflight(&mut self) {

        /*
        use crate::future::poll_fn;

        poll_fn(|cx| self.poll_complete_inflight(cx)).await
        */

        todo!();
    }

    fn poll_complete_inflight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        todo!();
        
        /*
        ready!(crate::trace::trace_leaf(cx));
        match self.poll_flush(cx) {
            Poll::Ready(Err(e)) => {
                self.last_write_err = Some(e.kind());
                Poll::Ready(())
            }
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
        */
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        
        todo!();
        
        /*
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
        */
    }
}
