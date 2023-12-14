//! Iterate and inspect file formats.
mod file_identity;
mod records;
mod stream;

pub use file_identity::FileIdentity;
pub use records::{EventLogFileRecord, FileItem, FileRecord, VaultRecord};
pub use stream::FormatStream;

use crate::{
    constants::{AUDIT_IDENTITY, VAULT_IDENTITY},
    vault::Header,
    vfs::File,
    Result,
};
use std::path::Path;

use futures::io::{BufReader, Cursor};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Type of a in-memory buffer for a stream.
pub type Buffer<'a> = BufReader<Cursor<&'a [u8]>>;

/// Type for a stream of event log records from a file.
pub type EventLogFileStream = FormatStream<EventLogFileRecord, Compat<File>>;

/// Type for a stream of event log records from a buffer.
pub type EventLogBufferStream<'a> =
    FormatStream<EventLogFileRecord, Buffer<'a>>;

/// Get a stream for a vault file.
pub async fn vault_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FormatStream<VaultRecord, Compat<File>>> {
    FileIdentity::read_file(path.as_ref(), &VAULT_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    let content_offset = Header::read_content_offset(path.as_ref()).await?;
    FormatStream::<VaultRecord, Compat<File>>::new_file(
        read_stream,
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
    .await
}

/// Get a stream for a vault file buffer.
pub async fn vault_stream_buffer<'a>(
    buffer: &'a [u8],
) -> Result<FormatStream<VaultRecord, Buffer<'a>>> {
    FileIdentity::read_slice(&buffer, &VAULT_IDENTITY)?;
    let content_offset = Header::read_content_offset_slice(&buffer).await?;
    let read_stream = BufReader::new(Cursor::new(buffer));
    FormatStream::<VaultRecord, Buffer<'a>>::new_buffer(
        read_stream,
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
    .await
}

/// Stream for an event log file.
pub async fn event_log_stream<P: AsRef<Path>>(
    path: P,
    identity: &'static [u8],
    content_offset: u64,
) -> Result<EventLogFileStream> {
    FileIdentity::read_file(path.as_ref(), &identity).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    FormatStream::<EventLogFileRecord, Compat<File>>::new_file(
        read_stream,
        &identity,
        true,
        Some(content_offset),
    )
    .await
}

/// Stream for an event log file buffer.
pub async fn event_log_stream_buffer<'a>(
    buffer: &'a [u8],
    identity: &'static [u8],
    content_offset: u64,
) -> Result<EventLogBufferStream<'a>> {
    FileIdentity::read_slice(&buffer, identity)?;
    let read_stream = BufReader::new(Cursor::new(buffer));
    FormatStream::<EventLogFileRecord, Buffer<'a>>::new_buffer(
        read_stream,
        identity,
        true,
        Some(content_offset),
    )
    .await
}

/*
/// Get a stream for a patch file.
pub async fn patch_stream<P: AsRef<Path>>(
    path: P,
) -> Result<EventLogFileStream> {
    FileIdentity::read_file(path.as_ref(), &PATCH_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    FormatStream::<EventLogFileRecord, Compat<File>>::new_file(
        read_stream,
        &PATCH_IDENTITY,
        false,
        None,
    )
    .await
}

/// Get a stream for a patch file buffer.
pub async fn patch_stream_buffer<'a>(
    buffer: &'a [u8],
) -> Result<EventLogBufferStream<'a>> {
    FileIdentity::read_slice(&buffer, &PATCH_IDENTITY)?;
    let read_stream = BufReader::new(Cursor::new(buffer));
    FormatStream::<EventLogFileRecord, Buffer<'a>>::new_buffer(
        read_stream,
        &PATCH_IDENTITY,
        false,
        None,
    )
    .await
}
*/

/// Get a stream for an audit file.
pub async fn audit_stream<P: AsRef<Path>>(
    path: P,
) -> Result<FormatStream<FileRecord, Compat<File>>> {
    FileIdentity::read_file(path.as_ref(), &AUDIT_IDENTITY).await?;
    let read_stream = File::open(path.as_ref()).await?.compat();
    FormatStream::<FileRecord, Compat<File>>::new_file(
        read_stream,
        &AUDIT_IDENTITY,
        false,
        None,
    )
    .await
}

/// Get a stream for an audit file buffer.
pub async fn audit_stream_buffer<'a>(
    buffer: &'a [u8],
) -> Result<FormatStream<FileRecord, Buffer<'a>>> {
    FileIdentity::read_slice(&buffer, &AUDIT_IDENTITY)?;
    let read_stream = BufReader::new(Cursor::new(buffer));
    FormatStream::<FileRecord, Buffer<'a>>::new_buffer(
        read_stream,
        &AUDIT_IDENTITY,
        false,
        None,
    )
    .await
}
