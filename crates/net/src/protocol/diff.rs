include!(concat!(env!("OUT_DIR"), "/diff.rs"));

use crate::sdk::{
    commit::{CommitHash, CommitProof},
    events::{EventLogType, EventRecord},
    Result,
};
use prost::bytes::Buf;

/// Request commit diff from an event log.
#[derive(Debug)]
pub struct DiffRequest {
    /// Type of event log to load the diff from.
    pub log_type: EventLogType,
    /// Hash of the commit to diff from.
    pub from_hash: Option<CommitHash>,
}

impl DiffRequest {
    /// Encode this request.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WireDiffRequest = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this request.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WireDiffRequest>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WireDiffRequest> for DiffRequest {
    type Error = crate::sdk::Error;

    fn try_from(value: WireDiffRequest) -> Result<Self> {
        let log_type =
            super::into_event_log_type(value.log_type, value.folder_id)?;
        let from_hash = if let Some(from_hash) = value.from_hash {
            Some(from_hash.try_into()?)
        } else {
            None
        };
        Ok(Self {
            log_type,
            from_hash,
        })
    }
}

impl From<DiffRequest> for WireDiffRequest {
    fn from(value: DiffRequest) -> WireDiffRequest {
        let (log_type, folder_id) =
            super::into_wire_event_log_type(value.log_type);
        Self {
            log_type,
            folder_id,
            from_hash: value.from_hash.map(|h| h.into()),
        }
    }
}

/// Response with an event log commit diff.
#[derive(Debug)]
pub struct DiffResponse {
    /// Collection of event records from the commit hash.
    pub patch: Vec<EventRecord>,
    /// Checkpoint of remote HEAD.
    pub checkpoint: CommitProof,
}

impl DiffResponse {
    /// Encode this response.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WireDiffResponse = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this response.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WireDiffResponse>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WireDiffResponse> for DiffResponse {
    type Error = crate::sdk::Error;

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
