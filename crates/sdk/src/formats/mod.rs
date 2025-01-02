//! Iterate and inspect file formats.
mod file_identity;
mod records;
pub(crate) mod stream;
use crate::{constants::AUDIT_IDENTITY, vfs::File, Result};
pub use file_identity::FileIdentity;
pub use records::{EventLogRecord, FileItem, FileRecord, VaultRecord};
use std::path::Path;
pub use stream::{FormatStream, FormatStreamIterator};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Get a stream for an audit file.
pub async fn audit_stream<P: AsRef<Path>>(
    path: P,
    reverse: bool,
) -> Result<FormatStream<FileRecord, Compat<File>>> {
    FileIdentity::read_file(path.as_ref(), &AUDIT_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    FormatStream::<FileRecord, Compat<File>>::new_file(
        read_stream,
        &AUDIT_IDENTITY,
        false,
        None,
        reverse,
    )
    .await
}
