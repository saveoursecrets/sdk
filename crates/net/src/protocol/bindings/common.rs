include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::{
    protocol::{decode_uuid, encode_uuid, Error, ProtoBinding, Result},
    sdk::{
        commit::{CommitHash, CommitProof, CommitState},
        events::{CheckedPatch, EventRecord},
        time::{Duration, OffsetDateTime},
        UtcDateTime,
    },
    sync::EventLogType,
};
use rs_merkle::{algorithms::Sha256, MerkleProof};

impl ProtoBinding for UtcDateTime {
    type Inner = WireUtcDateTime;
}

impl TryFrom<WireUtcDateTime> for UtcDateTime {
    type Error = Error;

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

impl ProtoBinding for CommitHash {
    type Inner = WireCommitHash;
}

impl TryFrom<WireCommitHash> for CommitHash {
    type Error = Error;

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

impl ProtoBinding for CommitProof {
    type Inner = WireCommitProof;
}

impl TryFrom<WireCommitProof> for CommitProof {
    type Error = Error;

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

impl ProtoBinding for CommitState {
    type Inner = WireCommitState;
}

impl TryFrom<WireCommitState> for CommitState {
    type Error = Error;

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

impl ProtoBinding for EventRecord {
    type Inner = WireEventRecord;
}

impl TryFrom<WireEventRecord> for EventRecord {
    type Error = Error;

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

impl ProtoBinding for CheckedPatch {
    type Inner = WireCheckedPatch;
}

impl TryFrom<WireCheckedPatch> for CheckedPatch {
    type Error = Error;

    fn try_from(value: WireCheckedPatch) -> Result<Self> {
        let inner = value.inner.unwrap();
        Ok(match inner {
            wire_checked_patch::Inner::Success(success) => {
                Self::Success(success.proof.unwrap().try_into()?)
            }
            wire_checked_patch::Inner::Conflict(conflict) => {
                let contains = if let Some(contains) = conflict.contains {
                    Some(contains.try_into()?)
                } else {
                    None
                };
                Self::Conflict {
                    head: conflict.head.unwrap().try_into()?,
                    contains,
                }
            }
        })
    }
}

impl From<CheckedPatch> for WireCheckedPatch {
    fn from(value: CheckedPatch) -> Self {
        match value {
            CheckedPatch::Success(proof) => WireCheckedPatch {
                inner: Some(wire_checked_patch::Inner::Success(
                    WireCheckedPatchSuccess {
                        proof: Some(proof.into()),
                    },
                )),
            },
            CheckedPatch::Conflict { head, contains } => WireCheckedPatch {
                inner: Some(wire_checked_patch::Inner::Conflict(
                    WireCheckedPatchConflict {
                        head: Some(head.into()),
                        contains: contains.map(|c| c.into()),
                    },
                )),
            },
        }
    }
}

impl ProtoBinding for EventLogType {
    type Inner = WireEventLogType;
}

impl TryFrom<WireEventLogType> for EventLogType {
    type Error = Error;

    fn try_from(value: WireEventLogType) -> Result<Self> {
        let inner = value.inner.unwrap();
        Ok(match inner {
            wire_event_log_type::Inner::User(value) => {
                EventLogType::Folder(decode_uuid(&value.folder_id)?)
            }
            wire_event_log_type::Inner::System(value) => {
                let value: WireEventLogTypeSystem = value.try_into()?;
                let name = value.as_str_name();
                match name {
                    "Identity" => EventLogType::Identity,
                    "Account" => EventLogType::Account,
                    #[cfg(feature = "device")]
                    "Device" => EventLogType::Device,
                    #[cfg(feature = "files")]
                    "Files" => EventLogType::Files,
                    _ => unreachable!(),
                }
            }
        })
    }
}

impl From<EventLogType> for WireEventLogType {
    fn from(value: EventLogType) -> Self {
        if let EventLogType::Folder(id) = &value {
            Self {
                inner: Some(wire_event_log_type::Inner::User(
                    WireEventLogTypeUser {
                        folder_id: encode_uuid(id),
                    },
                )),
            }
        } else {
            let system: i32 = match value {
                EventLogType::Identity => {
                    WireEventLogTypeSystem::from_str_name("Identity").unwrap()
                        as i32
                }
                EventLogType::Account => {
                    WireEventLogTypeSystem::from_str_name("Account").unwrap()
                        as i32
                }
                #[cfg(feature = "device")]
                EventLogType::Device => {
                    WireEventLogTypeSystem::from_str_name("Device").unwrap()
                        as i32
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    WireEventLogTypeSystem::from_str_name("Files").unwrap()
                        as i32
                }
                _ => unreachable!(),
            };

            Self {
                inner: Some(wire_event_log_type::Inner::System(system)),
            }
        }
    }
}
