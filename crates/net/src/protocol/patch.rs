include!(concat!(env!("OUT_DIR"), "/patch.rs"));

use prost::bytes::Buf;
use sos_sdk::sync::CheckedPatch;

use crate::sdk::{
    commit::{CommitHash, CommitProof},
    events::{EventLogType, EventRecord},
    Result,
};

/// Request to patch an event log from a specific commit.
///
/// Used during auto merge to force push a combined collection
/// of events.
#[derive(Debug, Default)]
pub struct PatchRequest {
    /// Type of event log to patch.
    pub log_type: EventLogType,
    /// Hash of a commit to rewind to before
    /// applying the patch.
    pub commit: Option<CommitHash>,
    /// Proof for HEAD of the event log before the
    /// events are applied.
    pub proof: CommitProof,
    /// Patch of events to apply.
    pub patch: Vec<EventRecord>,
}

impl PatchRequest {
    /// Encode this request.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WirePatchRequest = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this request.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WirePatchRequest>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WirePatchRequest> for PatchRequest {
    type Error = crate::sdk::Error;

    fn try_from(value: WirePatchRequest) -> Result<Self> {
        let log_type =
            super::into_event_log_type(value.log_type, value.folder_id)?;

        let commit = if let Some(commit) = value.commit {
            Some(commit.try_into()?)
        } else {
            None
        };

        let mut patch = Vec::with_capacity(value.patch.len());
        for event in value.patch {
            patch.push(event.try_into()?);
        }

        Ok(Self {
            log_type,
            commit,
            proof: value.proof.unwrap().try_into()?,
            patch,
        })
    }
}

impl From<PatchRequest> for WirePatchRequest {
    fn from(value: PatchRequest) -> WirePatchRequest {
        let (log_type, folder_id) =
            super::into_wire_event_log_type(value.log_type);
        Self {
            log_type,
            folder_id,
            commit: value.commit.map(|c| c.into()),
            proof: Some(value.proof.into()),
            patch: value.patch.into_iter().map(|e| e.into()).collect(),
        }
    }
}

/// Response from a patch request.
#[derive(Debug, Default)]
pub struct PatchResponse {
    /// Checked patch status.
    pub checked_patch: CheckedPatch,
}

impl PatchResponse {
    /// Encode this request.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WirePatchResponse = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this request.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WirePatchResponse>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WirePatchResponse> for PatchResponse {
    type Error = crate::sdk::Error;

    fn try_from(value: WirePatchResponse) -> Result<Self> {
        /*
        Ok(Self {
        })
        */
        todo!();
    }
}

impl From<PatchResponse> for WirePatchResponse {
    fn from(value: PatchResponse) -> WirePatchResponse {
        /*
        Self {
        }
        */
        todo!();
    }
}
