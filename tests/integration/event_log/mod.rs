use anyhow::Result;
use binary_stream::futures::{Decodable, Encodable};
use sos_net::{
    events::Patch,
    sdk::{commit::CommitHash, events::EventLogFile},
};

mod account_events;
mod compact_events;
mod file_events;
mod folder_events;
mod init_account_log;
mod init_file_log;

async fn last_log_event<T: Encodable + Decodable + Default>(
    event_log: &mut EventLogFile<T>,
    commit: Option<&CommitHash>,
) -> Result<Option<T>> {
    let records = event_log.patch_until(commit).await?;
    let patch: Patch = records.into();
    let mut events = patch.into_events::<T>().await?;
    Ok(events.pop())
}
