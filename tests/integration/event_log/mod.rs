use anyhow::Result;
use binary_stream::futures::{Decodable, Encodable};
use sos_net::{
    events::Patch,
    sdk::{commit::CommitHash, events::EventLogFile},
};

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
    event_log: &mut EventLogFile<T>,
    commit: Option<&CommitHash>,
) -> Result<Option<T>> {
    let records = event_log.diff_records(commit).await?;
    let patch: Patch = records.into();
    let mut events = patch.into_events::<T>().await?;
    Ok(events.pop())
}

/// Get all events from an event log.
async fn all_events<T: Encodable + Decodable + Default>(
    event_log: &mut EventLogFile<T>,
) -> Result<Vec<T>> {
    let records = event_log.diff_records(None).await?;
    let patch: Patch = records.into();
    Ok(patch.into_events::<T>().await?)
}
