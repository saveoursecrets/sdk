//! Iterate and inspect file formats.
use crate::Result;
use sos_core::constants::AUDIT_IDENTITY;
use sos_filesystem::formats::{
    read_file_identity_bytes, FileRecord, FormatStream,
};
use sos_vfs::File;
use std::path::Path;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Get a stream for an audit file.
pub async fn audit_stream<P: AsRef<Path>>(
    path: P,
    reverse: bool,
) -> Result<FormatStream<FileRecord, Compat<File>>> {
    read_file_identity_bytes(path.as_ref(), &AUDIT_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    Ok(FormatStream::<FileRecord, Compat<File>>::new_file(
        read_stream,
        &AUDIT_IDENTITY,
        false,
        None,
        reverse,
    )
    .await?)
}
