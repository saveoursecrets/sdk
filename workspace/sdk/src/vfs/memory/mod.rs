//! File system backed by in-memory buffers.

mod dir_builder;
mod file;
mod fs;
mod meta_data;
mod open_options;
mod read_dir;

pub use self::fs::*;
pub use dir_builder::{create_dir, create_dir_all, DirBuilder};
pub use file::File;
pub use meta_data::{FileType, Metadata, Permissions};
pub use open_options::OpenOptions;
pub use read_dir::*;

pub use std::path::PathBuf;

/// Result type for the in-memory file system.
pub type Result<T> = std::io::Result<T>;
