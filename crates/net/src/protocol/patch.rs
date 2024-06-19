include!(concat!(env!("OUT_DIR"), "/patch.rs"));

use super::{Error, ProtoBinding, Result};
use crate::sdk::{
    commit::{CommitHash, CommitProof},
    events::{CheckedPatch, EventLogType, EventRecord},
};

/// Request to patch an event log from a specific commit.
///
/// Used during auto merge to force push a combined collection
/// of events.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl ProtoBinding for PatchRequest {
    type Inner = WirePatchRequest;
}

impl TryFrom<WirePatchRequest> for PatchRequest {
    type Error = Error;

    fn try_from(value: WirePatchRequest) -> Result<Self> {
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
            log_type: value.log_type.unwrap().try_into()?,
            commit,
            proof: value.proof.unwrap().try_into()?,
            patch,
        })
    }
}

impl From<PatchRequest> for WirePatchRequest {
    fn from(value: PatchRequest) -> WirePatchRequest {
        Self {
            log_type: Some(value.log_type.into()),
            commit: value.commit.map(|c| c.into()),
            proof: Some(value.proof.into()),
            patch: value.patch.into_iter().map(|e| e.into()).collect(),
        }
    }
}

/// Response from a patch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchResponse {
    /// Checked patch status.
    pub checked_patch: CheckedPatch,
}

impl ProtoBinding for PatchResponse {
    type Inner = WirePatchResponse;
}

impl TryFrom<WirePatchResponse> for PatchResponse {
    type Error = Error;

    fn try_from(value: WirePatchResponse) -> Result<Self> {
        Ok(Self {
            checked_patch: value.checked_patch.unwrap().try_into()?,
        })
    }
}

impl From<PatchResponse> for WirePatchResponse {
    fn from(value: PatchResponse) -> WirePatchResponse {
        Self {
            checked_patch: Some(value.checked_patch.into()),
        }
    }
}
