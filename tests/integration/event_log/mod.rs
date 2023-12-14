use anyhow::Result;
use binary_stream::futures::{Decodable, Encodable};
use sos_net::sdk::{commit::CommitHash, events::{EventLogFile, FileLog}};

mod account_events;
mod change_password;
mod compact_events;
mod file_events;
mod folder_events;
mod import_folder;
mod init_account_log;
mod init_file_log;
mod move_folder;

/// Get the last event from an event log.
async fn last_log_event<T: Encodable + Decodable + Default>(
    event_log: &mut EventLogFile<T, FileLog>,
    commit: Option<&CommitHash>,
) -> Result<Option<T>> {
    let patch = event_log.diff(commit).await?;
    let mut events: Vec<T> = patch.into();
    Ok(events.pop())
}

/// Get all events from an event log.
async fn all_events<T: Encodable + Decodable + Default>(
    event_log: &mut EventLogFile<T, FileLog>,
) -> Result<Vec<T>> {
    let patch = event_log.diff(None).await?;
    Ok(patch.into())
}
