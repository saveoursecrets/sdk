//! Vault encrypted storage and access.
mod folder;
mod reducer;

pub use folder::{DiscFolder, Folder, MemoryFolder};
pub use reducer::FolderReducer;
pub use sos_vault::*;
