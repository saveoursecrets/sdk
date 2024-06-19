include!(concat!(env!("OUT_DIR"), "/diff.rs"));

use crate::{
    protocol::{Error, ProtoBinding, Result},
    sdk::{
        commit::{CommitHash, CommitProof},
        events::EventRecord,
    },
    sync::EventLogType,
};

/// Request commit diff from an event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRequest {
    /// Type of event log to load the diff from.
    pub log_type: EventLogType,
    /// Hash of the commit to diff from.
    pub from_hash: Option<CommitHash>,
}

impl ProtoBinding for DiffRequest {
    type Inner = WireDiffRequest;
}

impl TryFrom<WireDiffRequest> for DiffRequest {
    type Error = Error;

    fn try_from(value: WireDiffRequest) -> Result<Self> {
        let from_hash = if let Some(from_hash) = value.from_hash {
            Some(from_hash.try_into()?)
        } else {
            None
        };
        Ok(Self {
            log_type: value.log_type.unwrap().try_into()?,
            from_hash,
        })
    }
}

impl From<DiffRequest> for WireDiffRequest {
    fn from(value: DiffRequest) -> WireDiffRequest {
        Self {
            log_type: Some(value.log_type.into()),
            from_hash: value.from_hash.map(|h| h.into()),
        }
    }
}

/// Response with an event log commit diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffResponse {
    /// Collection of event records from the commit hash.
    pub patch: Vec<EventRecord>,
    /// Checkpoint of remote HEAD.
    pub checkpoint: CommitProof,
}

impl ProtoBinding for DiffResponse {
    type Inner = WireDiffResponse;
}

impl TryFrom<WireDiffResponse> for DiffResponse {
    type Error = Error;

    fn try_from(value: WireDiffResponse) -> Result<Self> {
        let mut events = Vec::with_capacity(value.patch.len());
        for patch in value.patch {
            events.push(patch.try_into()?);
        }
        Ok(Self {
            patch: events,
            checkpoint: value.checkpoint.unwrap().try_into()?,
        })
    }
}

impl From<DiffResponse> for WireDiffResponse {
    fn from(value: DiffResponse) -> WireDiffResponse {
        Self {
            patch: value.patch.into_iter().map(|p| p.into()).collect(),
            checkpoint: Some(value.checkpoint.into()),
        }
    }
}
