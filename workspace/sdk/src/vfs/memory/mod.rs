//! File system backed by in-memory buffers.

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
