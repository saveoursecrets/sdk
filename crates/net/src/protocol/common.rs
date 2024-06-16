include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::sdk::{commit, Result};
use rs_merkle::{algorithms::Sha256, MerkleProof};

impl TryFrom<WireCommitHash> for commit::CommitHash {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCommitHash) -> Result<Self> {
        let hash: [u8; 32] = value.hash.as_slice().try_into()?;
        Ok(commit::CommitHash(hash))
    }
}

impl From<commit::CommitHash> for WireCommitHash {
    fn from(value: commit::CommitHash) -> Self {
        Self {
            hash: value.as_ref().to_vec(),
        }
    }
}

impl TryFrom<WireCommitProof> for commit::CommitProof {
    type Error = crate::sdk::Error;

    fn try_from(value: WireCommitProof) -> Result<Self> {
        Ok(commit::CommitProof {
            root: value.root.unwrap().try_into()?,
            length: value.length as usize,
            proof: MerkleProof::<Sha256>::from_bytes(&value.proof)?,
            indices: value.indices.into_iter().map(|i| i as usize).collect(),
        })
    }
}

impl From<commit::CommitProof> for WireCommitProof {
    fn from(value: commit::CommitProof) -> Self {
        Self {
            root: Some(value.root.into()),
            proof: value.proof.to_bytes(),
            length: value.length as u64,
            indices: value.indices.into_iter().map(|i| i as u64).collect(),
        }
    }
}
