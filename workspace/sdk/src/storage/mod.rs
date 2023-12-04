//! Folder storage backed by the file system.

mod folders;
#[cfg(feature = "search")]
pub mod search;

pub use folders::FolderStorage;
