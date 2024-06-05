//! Run integrity checks on event logs.
use crate::events::{EventLogExt, FolderEventLog};
use crate::{
    commit::CommitTree,
    encoding::encoding_options,
    formats::{EventLogRecord, FileItem},
    vfs, Error, Result,
};

use async_stream::try_stream;
use binary_stream::futures::BinaryReader;
use futures::stream::Stream;
use std::{io::SeekFrom, path::Path};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Integrity check for an event log comparing the precomputed
/// checksums with the encrypted content of each row.
pub fn event_integrity(
    path: impl AsRef<Path>,
) -> impl Stream<Item = Result<Result<EventLogRecord>>> {
    try_stream! {
        let mut file = vfs::File::open(path.as_ref()).await?.compat();
        let mut reader = BinaryReader::new(&mut file, encoding_options());

        let event_log = FolderEventLog::new(path.as_ref()).await?;
        let mut it = event_log.iter(false).await?;
        let mut last_checksum: Option<[u8; 32]> = None;

        while let Some(record) = it.next().await? {
            // Verify the row last commit matches the checksum
            // for the previous row
            if let Some(last_checksum) = last_checksum {
                let expected_last_commit = record.last_commit();
                if last_checksum != expected_last_commit {
                    yield Err(Error::HashMismatch {
                        commit: hex::encode(expected_last_commit),
                        value: hex::encode(last_checksum),
                    });
                }
            }

            // Verify the commit hash for the data
            let commit = record.commit();
            let value = record.value();
            let length = value.end - value.start;
            reader.seek(SeekFrom::Start(value.start)).await?;
            let buffer = reader.read_bytes(length as usize).await?;

            let checksum = CommitTree::hash(&buffer);
            if checksum != commit {
                yield Err(Error::HashMismatch {
                    commit: hex::encode(commit),
                    value: hex::encode(checksum),
                });
            }

            last_checksum = Some(record.commit());

            yield Ok(record)
        }

    }
}
