use std::ffi::OsString;
use std::io::{ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::task::Context;
use std::task::Poll;

use super::{
    fs::{resolve, Fd, MemoryFd, PathTarget},
    metadata, FileType, Metadata,
};

/// Returns a stream over the entries within a directory.
pub async fn read_dir(path: impl AsRef<Path>) -> Result<ReadDir> {
    if let Some(target) = resolve(path.as_ref()).await {
        let children = match target {
            PathTarget::Root(dir) => dir.files().clone(),
            PathTarget::Descriptor(fd) => {
                let fd = fd.read().await;
                match &*fd {
                    MemoryFd::Dir(dir) => dir.files().clone(),
                    _ => return Err(ErrorKind::PermissionDenied.into()),
                }
            }
        };

        let mut files = Vec::new();
        for (name, fd) in children {
            let path = {
                let fd = fd.read().await;
                fd.path().await
            };
            files.push((name, path, fd))
        }
        Ok(ReadDir {
            iter: files.into_iter(),
        })
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Reads the entries in a directory.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct ReadDir {
    iter: std::vec::IntoIter<(OsString, PathBuf, Fd)>,
}

impl ReadDir {
    /// Returns the next entry in the directory stream.
    ///
    /// # Cancel safety
    ///
    /// This method is cancellation safe.
    pub async fn next_entry(&mut self) -> Result<Option<DirEntry>> {
        use std::future::poll_fn;
        poll_fn(|cx| self.poll_next_entry(cx)).await
    }

    /// Polls for the next directory entry in the stream.
    pub fn poll_next_entry(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<DirEntry>>> {
        if let Some((name, path, fd)) = self.iter.next() {
            let entry = DirEntry { path, name };
            Poll::Ready(Ok(Some(entry)))
        } else {
            Poll::Ready(Ok(None))
        }
    }
}

/// Entries returned by the [`ReadDir`] stream.
#[derive(Debug)]
pub struct DirEntry {
    path: PathBuf,
    name: OsString,
}

impl DirEntry {
    /// Returns the full path to the file that this entry represents.
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Returns the bare file name of this directory entry
    /// without any other leading path component.
    pub fn file_name(&self) -> OsString {
        self.name.clone()
    }

    /// Returns the metadata for the file that this entry points at.
    pub async fn metadata(&self) -> Result<Metadata> {
        metadata(&self.path).await
    }

    /// Returns the file type for the file that this entry points at.
    pub async fn file_type(&self) -> Result<FileType> {
        Ok(self.metadata().await?.file_type())
    }
}
