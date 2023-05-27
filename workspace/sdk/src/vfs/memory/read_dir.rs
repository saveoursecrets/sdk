use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{FileType, Metadata};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use tokio::task::JoinHandle;

const CHUNK_SIZE: usize = 32;

/// Returns a stream over the entries within a directory.
pub async fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
    todo!();
}

/// Reads the entries in a directory.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct ReadDir(State);

#[derive(Debug)]
enum State {
    Idle(Option<(VecDeque<io::Result<DirEntry>>, std::fs::ReadDir, bool)>),
    Pending(
        JoinHandle<(VecDeque<io::Result<DirEntry>>, std::fs::ReadDir, bool)>,
    ),
}

impl ReadDir {
    /// Returns the next entry in the directory stream.
    ///
    /// # Cancel safety
    ///
    /// This method is cancellation safe.
    pub async fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
        use std::future::poll_fn;
        poll_fn(|cx| self.poll_next_entry(cx)).await
    }

    /// Polls for the next directory entry in the stream.
    pub fn poll_next_entry(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<DirEntry>>> {

        todo!();

        /*
        loop {
            match self.0 {
                State::Idle(ref mut data) => {
                    let (buf, _, ref remain) = data.as_mut().unwrap();

                    if let Some(ent) = buf.pop_front() {
                        return Poll::Ready(ent.map(Some));
                    } else if !remain {
                        return Poll::Ready(Ok(None));
                    }

                    let (mut buf, mut std, _) = data.take().unwrap();

                    self.0 = State::Pending(spawn_blocking(move || {
                        let remain = ReadDir::next_chunk(&mut buf, &mut std);
                        (buf, std, remain)
                    }));
                }
                State::Pending(ref mut rx) => {
                    self.0 =
                        State::Idle(Some(ready!(Pin::new(rx).poll(cx))?));
                }
            }
        }
        */
    }

    fn next_chunk(
        buf: &mut VecDeque<io::Result<DirEntry>>,
        std: &mut std::fs::ReadDir,
    ) -> bool {
        todo!();

        /*
        for _ in 0..CHUNK_SIZE {
            let ret = match std.next() {
                Some(ret) => ret,
                None => return false,
            };

            let success = ret.is_ok();

            buf.push_back(ret.map(|std| DirEntry {
                #[cfg(not(any(
                    target_os = "solaris",
                    target_os = "illumos",
                    target_os = "haiku",
                    target_os = "vxworks"
                )))]
                file_type: std.file_type().ok(),
                std: Arc::new(std),
            }));

            if !success {
                break;
            }
        }

        true
        */
    }
}

/// Entries returned by the [`ReadDir`] stream.
#[derive(Debug)]
pub struct DirEntry {
    /*
    file_type: Option<FileType>,
    */
}

impl DirEntry {
    /// Returns the full path to the file that this entry represents.
    pub fn path(&self) -> PathBuf {
        todo!();
    }

    /// Returns the bare file name of this directory entry 
    /// without any other leading path component.
    pub fn file_name(&self) -> OsString {
        todo!();
    }

    /// Returns the metadata for the file that this entry points at.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        todo!();
    }

    /// Returns the file type for the file that this entry points at.
    pub async fn file_type(&self) -> io::Result<FileType> {
        todo!();
    }
}
