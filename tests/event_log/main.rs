use anyhow::Result;
use binary_stream::futures::{Decodable, Encodable};
use sos_net::sdk::{
    commit::CommitHash,
    events::DiscEventLog,
    events::{EventLogExt, LogEvent},
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

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;

/// Get the last event from an event log.
async fn last_log_event<
    T: LogEvent + Encodable + Decodable + Default + Send + Sync + 'static,
>(
    event_log: &mut DiscEventLog<T>,
    commit: Option<&CommitHash>,
) -> Result<Option<T>> {
    let patch = event_log.diff_events(commit).await?;
    let mut events: Vec<T> = patch.into_events().await?;
    Ok(events.pop())
}

/// Get all events from an event log.
async fn all_events<
    T: LogEvent + Encodable + Decodable + Default + Send + Sync + 'static,
>(
    event_log: &mut DiscEventLog<T>,
) -> Result<Vec<T>> {
    let patch = event_log.diff_events(None).await?;
    Ok(patch.into_events().await?)
}
