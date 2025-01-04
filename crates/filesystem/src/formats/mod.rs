//! Iterate and inspect file formats.
mod file_identity;
mod records;
pub(crate) mod stream;

pub use file_identity::read_file_identity_bytes;
pub use records::{EventLogRecord, FileItem, FileRecord, VaultRecord};
pub use stream::{FormatStream, FormatStreamIterator};
