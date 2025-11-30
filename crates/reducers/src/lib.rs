//! Reduce event logs into compact representations.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod device;
#[cfg(feature = "files")]
mod files;
mod folder;

pub use device::DeviceReducer;
#[cfg(feature = "files")]
pub use files::FileReducer;
pub use folder::FolderReducer;
