//! Types that encapsulate commit proofs and comparisons.
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    hash::{Hash, Hasher as StdHasher},
    str::FromStr,
};

use super::TreeHash;
use rs_merkle::{algorithms::Sha256, MerkleProof};

/// Hash representation that provides a hexadecimal display.
#[derive(
    Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Hash,
)]
pub struct CommitHash(#[serde(with = "hex::serde")] pub TreeHash);

impl AsRef<TreeHash> for CommitHash {
    fn as_ref(&self) -> &TreeHash {
        &self.0
    }
}

impl From<&CommitHash> for [u8; 32] {
    fn from(value: &CommitHash) -> Self {
        value.0
    }
}

impl fmt::Display for CommitHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for CommitHash {
    type Err = crate::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = hex::decode(value)?;
        let value: TreeHash = value.as_slice().try_into()?;
        Ok(Self(value))
    }
}

/// The result of comparing two commit trees.
///
/// Either the trees are equal, the other tree
/// is a subset of this tree or the trees completely
/// diverge.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum Comparison {
    /// Trees are equal as their root commits match.
    Equal,
    /// Tree contains the other proof.
    Contains(Vec<usize>, Vec<TreeHash>),
    /// Unable to find a match against the proof.
    #[default]
    Unknown,
}

/// Represents a root hash and a proof of certain nodes.
pub struct CommitProof {
    /// Root hash.
    pub root: CommitHash,
    /// The merkle proof.
    pub proof: MerkleProof<Sha256>,
    /// The length of the tree.
    pub length: usize,
    /// Indices to prove.
    pub indices: Vec<usize>,
}

impl Hash for CommitProof {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.proof.proof_hashes().hash(state);
        self.length.hash(state);
        self.indices.hash(state);
    }
}

impl PartialEq for CommitProof {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.proof.proof_hashes() == other.proof.proof_hashes()
            && self.length == other.length
            && self.indices == other.indices
    }
}

impl Eq for CommitProof {}

impl Clone for CommitProof {
    fn clone(&self) -> Self {
        let hashes = self.proof.proof_hashes().to_vec();
        CommitProof {
            root: self.root,
            proof: MerkleProof::<Sha256>::new(hashes),
            length: self.length,
            indices: self.indices.clone(),
        }
    }
}

impl CommitProof {
    /// Root hash for the proof.
    pub fn root(&self) -> &CommitHash {
        &self.root
    }

    /// Number of leaves in the commit tree.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Determine if this proof is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verify the indices of this proof using
    /// a slice of leaves.
    pub fn verify_leaves(
        &self,
        leaves: &[TreeHash],
    ) -> (bool, Vec<TreeHash>) {
        let leaves_to_prove = self
            .indices
            .iter()
            .filter_map(|i| leaves.get(*i))
            .copied()
            .collect::<Vec<_>>();
        (
            self.proof.verify(
                self.root().into(),
                &self.indices,
                leaves_to_prove.as_slice(),
                leaves.len(),
            ),
            leaves_to_prove,
        )
    }
}

impl From<CommitProof> for (CommitHash, usize) {
    fn from(value: CommitProof) -> Self {
        (value.root, value.length)
    }
}

impl From<CommitProof> for CommitHash {
    fn from(value: CommitProof) -> Self {
        value.root
    }
}

impl Default for CommitProof {
    fn default() -> Self {
        Self {
            root: Default::default(),
            proof: MerkleProof::<Sha256>::new(vec![]),
            length: 0,
            indices: vec![],
        }
    }
}

impl fmt::Debug for CommitProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitProof")
            .field("root", &self.root.to_string())
            //.field("proofs", self.1.proof_hashes())
            .field("length", &self.length)
            .field("indices", &self.indices)
            .finish()
    }
}
