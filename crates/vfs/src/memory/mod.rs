//! File system backed by in-memory buffers.
#![allow(unused_imports)]

use std::path::Path;

mod dir_builder;
mod file;
mod fs;
mod meta_data;
mod open_options;
mod read_dir;

pub use dir_builder::{create_dir, create_dir_all, DirBuilder};
pub use file::File;
pub use fs::{
    canonicalize, copy, metadata, read, read_to_string, remove_dir,
    remove_dir_all, remove_file, rename, set_permissions, try_exists, write,
};
pub use meta_data::{FileType, Metadata, Permissions};
pub use open_options::OpenOptions;
pub use read_dir::{read_dir, DirEntry};

/// Write acquiring an exclusive lock.
///
/// Currently a NOOP for the in-memory implementation.
pub async fn write_exclusive(
    path: impl AsRef<Path>,
    buf: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    write(path, buf).await
}

/// Read acquiring an exclusive lock.
///
/// Currently a NOOP for the in-memory implementation.
pub async fn read_exclusive(
    path: impl AsRef<Path>,
) -> std::io::Result<Vec<u8>> {
    read(path).await
}

/// Read acquiring a shared read lock.
///
/// Currently a NOOP for the in-memory implementation.
pub async fn read_shared(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    read(path).await
}
