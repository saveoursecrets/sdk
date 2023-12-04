//! Folder storage backed by the file system.

#[cfg(feature = "files")]
pub mod files;
mod folders;
#[cfg(feature = "search")]
pub mod search;

pub use folders::FolderStorage;
