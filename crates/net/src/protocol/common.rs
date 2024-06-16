include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::sdk::{
    commit::{CommitHash, CommitProof, CommitState},
    events::EventRecord,
    sync::CheckedPatch,
    time::{Duration, OffsetDateTime},
    Result, UtcDateTime,
};
use rs_merkle::{algorithms::Sha256, MerkleProof};

impl TryFrom<WireUtcDateTime> for UtcDateTime {
    type Error = crate::sdk::Error;

    fn try_from(value: WireUtcDateTime) -> Result<Self> {
        let time = OffsetDateTime::from_unix_timestamp(value.seconds)?
            + Duration::nanoseconds(value.nanos as i64);
        Ok(time.into())
    }
}

impl From<UtcDateTime> for WireUtcDateTime {
    fn from(value: UtcDateTime) -> Self {
        let time: OffsetDateTime = value.into();
        Self {
            seconds: time.unix_timestamp(),
            nanos: time.nanosecond(),
        }
    }
}

impl TryFrom<WireCommitHash> for CommitHash {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCommitHash) -> Result<Self> {
        let hash: [u8; 32] = value.hash.as_slice().try_into()?;
        Ok(CommitHash(hash))
    }
}

impl From<CommitHash> for WireCommitHash {
    fn from(value: CommitHash) -> Self {
        Self {
            hash: value.as_ref().to_vec(),
        }
    }
}

impl TryFrom<WireCommitProof> for CommitProof {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCommitProof) -> Result<Self> {
        Ok(CommitProof {
            root: value.root.unwrap().try_into()?,
            length: value.length as usize,
            proof: MerkleProof::<Sha256>::from_bytes(&value.proof)?,
            indices: value.indices.into_iter().map(|i| i as usize).collect(),
        })
    }
}

impl From<CommitProof> for WireCommitProof {
    fn from(value: CommitProof) -> Self {
        Self {
            root: Some(value.root.into()),
            proof: value.proof.to_bytes(),
            length: value.length as u64,
            indices: value.indices.into_iter().map(|i| i as u64).collect(),
        }
    }
}

impl TryFrom<WireCommitState> for CommitState {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCommitState) -> Result<Self> {
        Ok(CommitState(
            value.hash.unwrap().try_into()?,
            value.proof.unwrap().try_into()?,
        ))
    }
}

impl From<CommitState> for WireCommitState {
    fn from(value: CommitState) -> Self {
        Self {
            hash: Some(value.0.into()),
            proof: Some(value.1.into()),
        }
    }
}

impl TryFrom<WireEventRecord> for EventRecord {
    type Error = crate::sdk::Error;

    fn try_from(value: WireEventRecord) -> Result<Self> {
        Ok(EventRecord::new(
            value.time.unwrap().try_into()?,
            value.last_commit.unwrap().try_into()?,
            value.commit.unwrap().try_into()?,
            value.event,
        ))
    }
}

impl From<EventRecord> for WireEventRecord {
    fn from(value: EventRecord) -> Self {
        let (time, last_commit, commit, event): (
            UtcDateTime,
            CommitHash,
            CommitHash,
            Vec<u8>,
        ) = value.into();
        Self {
            time: Some(time.into()),
            last_commit: Some(last_commit.into()),
            commit: Some(commit.into()),
            event,
        }
    }
}

impl TryFrom<WireCheckedPatch> for CheckedPatch {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCheckedPatch) -> Result<Self> {
        if let Some(conflict) = value.conflict {
            let contains = if let Some(contains) = conflict.contains {
                Some(contains.try_into()?)
            } else {
                None
            };
            Ok(Self::Conflict {
                head: conflict.head.unwrap().try_into()?,
                contains,
            })
        } else if let Some(success) = value.success {
            Ok(Self::Success(success.proof.unwrap().try_into()?))
        } else {
            unreachable!();
        }
    }
}

impl From<CheckedPatch> for WireCheckedPatch {
    fn from(value: CheckedPatch) -> Self {
        match value {
            CheckedPatch::Noop => unreachable!(),
            CheckedPatch::Success(proof) => WireCheckedPatch {
                success: Some(WireCheckedPatchSuccess {
                    proof: Some(proof.into()),
                }),
                conflict: None,
            },
            CheckedPatch::Conflict { head, contains } => WireCheckedPatch {
                success: None,
                conflict: Some(WireCheckedPatchConflict {
                    head: Some(head.into()),
                    contains: contains.map(|c| c.into()),
                }),
            },
        }
    }
}
