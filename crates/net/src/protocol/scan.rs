include!(concat!(env!("OUT_DIR"), "/scan.rs"));

use crate::sdk::{commit::CommitProof, events::EventLogType, Result};
use prost::bytes::Buf;

/// Request commit proofs from an event log.
#[derive(Debug, Default, Clone)]
pub struct ScanRequest {
    /// Type of event log to load commit hashes from.
    pub log_type: EventLogType,
    /// Number of proofs to fetch.
    ///
    /// Server implementations should restrict this to
    /// a sensible amount; the default server implementation
    /// imposes a limit of 256 proofs.
    pub limit: u16,
    /// Offset from a previous scan used as a hint to
    /// continue scanning.
    pub offset: Option<u64>,
}

impl ScanRequest {
    /// Encode this request.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WireScanRequest = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this request.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WireScanRequest>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WireScanRequest> for ScanRequest {
    type Error = crate::sdk::Error;

    fn try_from(value: WireScanRequest) -> Result<Self> {
        let log_type =
            super::into_event_log_type(value.log_type, value.folder_id)?;
        Ok(Self {
            log_type,
            limit: value.limit.unwrap() as u16,
            offset: value.offset,
        })
    }
}

impl From<ScanRequest> for WireScanRequest {
    fn from(value: ScanRequest) -> WireScanRequest {
        let (log_type, folder_id) =
            super::into_wire_event_log_type(value.log_type);
        Self {
            log_type,
            folder_id,
            limit: Some(value.limit as u32),
            offset: value.offset,
        }
    }
}

/// Commit proofs from an event log.
#[derive(Debug, Default)]
pub struct ScanResponse {
    /// Proof for the first item in the event log.
    pub first_proof: Option<CommitProof>,
    /// List of commit proofs.
    ///
    /// Proofs are always listed in the order they
    /// appear in the event log regardless of the scan
    /// direction.
    pub proofs: Vec<CommitProof>,
    /// Offset that can be used to continue scanning.
    pub offset: u64,
}

impl ScanResponse {
    /// Encode this response.
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let value: WireScanResponse = self.into();
        Ok(super::encode(&value)?)
    }

    /// Decode this response.
    pub fn decode(buffer: impl Buf) -> crate::Result<Self> {
        let result = super::decode::<WireScanResponse>(buffer)?;
        Ok(result.try_into()?)
    }
}

impl TryFrom<WireScanResponse> for ScanResponse {
    type Error = crate::sdk::Error;

    fn try_from(value: WireScanResponse) -> Result<Self> {
        let first_proof = if let Some(first_proof) = value.first_proof {
            Some(first_proof.try_into()?)
        } else {
            None
        };

        let mut proofs = Vec::with_capacity(value.proofs.len());
        for proof in value.proofs {
            proofs.push(proof.try_into()?);
        }

        Ok(Self {
            first_proof,
            proofs,
            offset: value.offset,
        })
    }
}

impl From<ScanResponse> for WireScanResponse {
    fn from(value: ScanResponse) -> WireScanResponse {
        Self {
            first_proof: value.first_proof.map(|p| p.into()),
            proofs: value.proofs.into_iter().map(|p| p.into()).collect(),
            offset: value.offset,
        }
    }
}
