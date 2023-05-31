//! Iterate and inspect file formats.
mod file_identity;
mod records;
mod stream;

pub use file_identity::FileIdentity;
pub use records::{EventLogFileRecord, FileItem, FileRecord, VaultRecord};
pub use stream::FileStream;

use crate::{
    constants::{
        AUDIT_IDENTITY, EVENT_LOG_IDENTITY, PATCH_IDENTITY, VAULT_IDENTITY,
    },
    vault::Header,
    vfs::File,
    Result,
};
use std::path::Path;

/// Get a stream for a vault file.
pub async fn vault_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FileStream<VaultRecord, File>> {
    let content_offset = Header::read_content_offset(path.as_ref()).await?;
    FileStream::<VaultRecord, File>::new_file(
        path.as_ref(),
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
    .await
}

/// Get a stream for a event log file.
pub async fn event_log_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FileStream<EventLogFileRecord, File>> {
    FileStream::<EventLogFileRecord, File>::new_file(
        path.as_ref(),
        &EVENT_LOG_IDENTITY,
        true,
        None,
    )
    .await
}

/// Get a stream for a patch file.
pub async fn patch_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FileStream<FileRecord, File>> {
    FileStream::<FileRecord, File>::new_file(
        path.as_ref(),
        &PATCH_IDENTITY,
        false,
        None,
    )
    .await
}

/// Get a stream for an audit file.
pub async fn audit_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FileStream<FileRecord, File>> {
    FileStream::<FileRecord, File>::new_file(
        path.as_ref(),
        &AUDIT_IDENTITY,
        false,
        None,
    )
    .await
}
