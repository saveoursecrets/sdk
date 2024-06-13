//! Types that encapsulate commit proofs and comparisons.

use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Serialize,
};
use std::{
    fmt,
    hash::{Hash, Hasher as StdHasher},
};

use rs_merkle::{algorithms::Sha256, MerkleProof};

/// Hash representation that provides a hexadecimal display.
#[derive(
    Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Hash,
)]
pub struct CommitHash(#[serde(with = "hex::serde")] pub [u8; 32]);

impl AsRef<[u8; 32]> for CommitHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<CommitHash> for [u8; 32] {
    fn from(value: CommitHash) -> Self {
        value.0
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
    Contains(Vec<usize>, Vec<[u8; 32]>),
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
            .field("size", &self.length)
            .field("leaves", &self.indices)
            .finish()
    }
}

impl serde::Serialize for CommitProof {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // 4-element tuple
        let mut tup = serializer.serialize_tuple(4)?;
        let root_hash = self.root.to_string();
        tup.serialize_element(&root_hash)?;
        let hashes = self.proof.proof_hashes();
        tup.serialize_element(hashes)?;
        tup.serialize_element(&self.length)?;
        tup.serialize_element(&self.indices)?;
        tup.end()
    }
}

struct CommitProofVisitor;

impl<'de> Visitor<'de> for CommitProofVisitor {
    type Value = CommitProof;

    fn expecting(&self, _formatter: &mut fmt::Formatter) -> fmt::Result {
        Ok(())
    }

    fn visit_seq<A>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let root_hash: String = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting a root hash for commit proof")
        })?;
        let root_hash = hex::decode(root_hash).map_err(de::Error::custom)?;
        let root_hash: [u8; 32] =
            root_hash.as_slice().try_into().map_err(de::Error::custom)?;
        let root_hash = CommitHash(root_hash);
        let hashes: Vec<[u8; 32]> = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting sequence of proof hashes")
        })?;
        let length: usize = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting tree length usize")
        })?;

        let indices: Vec<usize> = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("expecting indices to prove"))?;
        Ok(CommitProof {
            root: root_hash,
            proof: MerkleProof::new(hashes),
            length,
            indices,
        })
    }
}

impl<'de> serde::Deserialize<'de> for CommitProof {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<CommitProof, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_tuple(4, CommitProofVisitor)
    }
}
