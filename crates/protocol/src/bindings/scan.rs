include!(concat!(env!("OUT_DIR"), "/scan.rs"));

use crate::{
    sdk::commit::CommitProof, Error, EventLogType, ProtoBinding, Result,
};

/// Request commit proofs from an event log.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub offset: u64,
}

impl ProtoBinding for ScanRequest {
    type Inner = WireScanRequest;
}

impl TryFrom<WireScanRequest> for ScanRequest {
    type Error = Error;

    fn try_from(value: WireScanRequest) -> Result<Self> {
        Ok(Self {
            log_type: value.log_type.unwrap().try_into()?,
            limit: value.limit.unwrap() as u16,
            offset: value.offset,
        })
    }
}

impl From<ScanRequest> for WireScanRequest {
    fn from(value: ScanRequest) -> WireScanRequest {
        Self {
            log_type: Some(value.log_type.into()),
            limit: Some(value.limit as u32),
            offset: value.offset,
        }
    }
}

/// Commit proofs from an event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResponse {
    /// Proof for the first item in the event log.
    pub first_proof: Option<CommitProof>,
    /// List of commit proofs.
    ///
    /// Proofs are listed in the order they
    /// appear in the event log.
    pub proofs: Vec<CommitProof>,
    /// Offset that can be used to continue scanning.
    pub offset: u64,
}

impl ProtoBinding for ScanResponse {
    type Inner = WireScanResponse;
}

impl TryFrom<WireScanResponse> for ScanResponse {
    type Error = Error;

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
