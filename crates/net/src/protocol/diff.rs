include!(concat!(env!("OUT_DIR"), "/diff.rs"));

use crate::sdk::{
    commit::{CommitHash, CommitProof},
    events::{EventLogType, EventRecord},
};

/// Request commit diff from an event log.
#[derive(Debug, Default)]
pub struct DiffRequest {
    /// Type of event log to load the diff from.
    pub log_type: EventLogType,
    /// Hash of the commit to diff from.
    pub from_hash: Option<CommitHash>,
}

/// Response with an event log commit diff.
#[derive(Debug, Default)]
pub struct DiffResponse {
    /// Collection of event records from the commit hash.
    pub patch: Vec<EventRecord>,
    /// Checkpoint of remote HEAD.
    pub checkpoint: CommitProof,
}
