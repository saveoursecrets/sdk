//! Compact folders.
use crate::BackendEventLog;
use crate::Error;
use crate::FolderEventLog;
use crate::{reducers::FolderReducer, Result};
use sos_core::events::EventLog;
use sos_filesystem::FolderEventLog as FsFolderEventLog;
use sos_vfs as vfs;
use tempfile::NamedTempFile;

/// Compact a filesystem folder event log.
pub async fn compact_filesystem_folder(
    event_log: &FolderEventLog,
) -> Result<(FolderEventLog, u64, u64)> {
    match event_log {
        BackendEventLog::Database(event_log) => {
            todo!("handle compacting database folder...");
        }
        BackendEventLog::FileSystem(event_log) => {
            let file = event_log.file_path().to_owned();
            let old_size = file.metadata()?.len();

            // Get the reduced set of events
            let events = FolderReducer::new()
                .reduce(event_log)
                .await?
                .compact()
                .await?;
            let temp = NamedTempFile::new()?;

            // Apply them to a temporary event log file
            let mut temp_event_log =
                FsFolderEventLog::<Error>::new(temp.path()).await?;
            temp_event_log.apply(events.iter().collect()).await?;

            let new_size = file.metadata()?.len();

            // Remove the existing event log file
            vfs::remove_file(&file).await?;

            // Move the temp file into place
            //
            // NOTE: we would prefer to rename but on linux we
            // NOTE: can hit ErrorKind::CrossesDevices
            //
            // But it's a nightly only variant so can't use it yet to
            // determine whether to rename or copy.
            vfs::copy(temp.path(), &file).await?;

            // Need to recreate the event log file and load the updated
            // commit tree
            let mut new_event_log =
                FsFolderEventLog::<Error>::new(&file).await?;
            new_event_log.load_tree().await?;

            Ok((
                BackendEventLog::FileSystem(new_event_log),
                old_size,
                new_size,
            ))
        }
    }
}
