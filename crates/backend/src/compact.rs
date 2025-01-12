//! Compact folders.
use crate::{
    reducers::FolderReducer, BackendEventLog, Error, FolderEventLog, Result,
};
use sos_core::events::{
    patch::{FolderDiff, Patch},
    EventLog, EventRecord,
};
use sos_database::db::open_memory;
use sos_filesystem::FolderEventLog as FsFolderEventLog;
use tempfile::NamedTempFile;

/// Compact a folder event log.
pub async fn compact_folder(event_log: &mut FolderEventLog) -> Result<()> {
    match event_log {
        BackendEventLog::Database(event_log) => {
            // Get the reduced set of events
            let events = FolderReducer::new()
                .reduce(event_log)
                .await?
                .compact()
                .await?;

            // Apply them to a temporary event log file so we can compute
            // a checkpoint for the diff
            let client = open_memory().await?;
            let mut temp_event_log = event_log.with_new_client(client);
            temp_event_log.apply(events.iter().collect()).await?;

            let mut records = Vec::new();
            for event in &events {
                records.push(EventRecord::encode_event(event).await?);
            }

            let diff = FolderDiff::new(
                Patch::new(records),
                temp_event_log
                    .tree()
                    .proof(&[temp_event_log.tree().len() - 1])?,
                None,
            );
            event_log.replace_all_events(&diff).await?;

            Ok(())
        }
        BackendEventLog::FileSystem(event_log) => {
            // Get the reduced set of events
            let events = FolderReducer::new()
                .reduce(event_log)
                .await?
                .compact()
                .await?;

            // Apply them to a temporary event log file
            let temp = NamedTempFile::new()?;
            let mut temp_event_log =
                FsFolderEventLog::<Error>::new_folder(temp.path()).await?;
            temp_event_log.apply(events.iter().collect()).await?;

            let mut records = Vec::new();
            for event in &events {
                records.push(EventRecord::encode_event(event).await?);
            }

            let diff = FolderDiff::new(
                Patch::new(records),
                temp_event_log
                    .tree()
                    .proof(&[temp_event_log.tree().len() - 1])?,
                None,
            );

            event_log.replace_all_events(&diff).await?;

            temp.close()?;

            Ok(())
        }
    }
}
