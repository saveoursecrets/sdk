#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Reduce event logs into compact representations.

mod device;
#[cfg(feature = "files")]
mod files;
mod folder;

pub use device::DeviceReducer;
#[cfg(feature = "files")]
pub use files::FileReducer;
pub use folder::FolderReducer;
