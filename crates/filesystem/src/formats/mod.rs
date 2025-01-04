//! Iterate and inspect file formats.
mod file_identity;
mod records;
pub(crate) mod stream;

pub use file_identity::FileIdentity;
pub use records::{EventLogRecord, FileItem, FileRecord, VaultRecord};
pub use stream::{FormatStream, FormatStreamIterator};
