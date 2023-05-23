//! Types that encapsulate commit proofs and comparisons.
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Serialize,
};
use std::{
    fmt,
    hash::{Hash, Hasher as StdHasher},
    io::{Read, Seek, Write},
    ops::Range,
};

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};

/// Hash representation that provides a hexadecimal display.
#[derive(
    Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct CommitHash(#[serde(with = "hex::serde")] pub [u8; 32]);

impl AsRef<[u8; 32]> for CommitHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl CommitHash {
    /// Get a copy of the underlying bytes for the commit hash.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<CommitHash> for [u8; 32] {
    fn from(value: CommitHash) -> Self {
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
#[derive(Debug, Eq, PartialEq)]
pub enum Comparison {
    /// Trees are equal as their root commits match.
    Equal,
    /// Tree contains the other proof.
    Contains(Vec<usize>, Vec<[u8; 32]>),
    /// Unable to find a match against the proof.
    Unknown,
}

/// Represents a root hash and a proof of certain nodes.
pub struct CommitProof {
    /// Root hash.
    pub root: <Sha256 as Hasher>::Hash,
    /// The merkle proof.
    pub proof: MerkleProof<Sha256>,
    /// The length of the tree.
    pub length: usize,
    /// Range of indices.
    pub indices: Range<usize>,
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
    /// The root hash for the proof.
    pub fn root(&self) -> &<Sha256 as Hasher>::Hash {
        &self.root
    }

    /// The root hash for the proof as hexadecimal.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
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
        (CommitHash(value.root), value.length)
    }
}

impl Default for CommitProof {
    fn default() -> Self {
        Self {
            root: [0; 32],
            proof: MerkleProof::<Sha256>::new(vec![]),
            length: 0,
            indices: 0..0,
        }
    }
}

impl Encode for CommitProof {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(self.root)?;
        let proof_bytes = self.proof.to_bytes();
        writer.write_u32(proof_bytes.len() as u32)?;
        writer.write_bytes(&proof_bytes)?;

        writer.write_u32(self.length as u32)?;
        writer.write_u32(self.indices.start as u32)?;
        writer.write_u32(self.indices.end as u32)?;
        Ok(())
    }
}

impl Decode for CommitProof {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let root_hash: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        self.root = root_hash;
        let length = reader.read_u32()?;
        let proof_bytes = reader.read_bytes(length as usize)?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(Box::from)?;

        self.proof = proof;
        self.length = reader.read_u32()? as usize;
        let start = reader.read_u32()?;
        let end = reader.read_u32()?;

        // TODO: validate range start is <= range end

        self.indices = start as usize..end as usize;
        Ok(())
    }
}

impl fmt::Debug for CommitProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitProof")
            .field("root", &hex::encode(self.root))
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
        let root_hash = hex::encode(self.root);
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
        let hashes: Vec<[u8; 32]> = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting sequence of proof hashes")
        })?;
        let length: usize = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting tree length usize")
        })?;
        let indices: Range<usize> = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("expecting leaf node range"))?;
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

/// Pair of commit proofs.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct CommitPair {
    /// Commit proof for a local commit tree.
    pub local: CommitProof,
    /// Commit proof for a remote commit tree.
    pub remote: CommitProof,
}

/// Relationship between two trees.
#[derive(Debug)]
pub enum CommitRelationship {
    /// Local and remote are equal.
    Equal(CommitPair),
    /// Local tree is ahead of the remote.
    ///
    /// A push operation should be successful.
    ///
    /// Includes the number of commits ahead.
    Ahead(CommitPair, usize),
    /// Local tree is behind the remote.
    ///
    /// A pull operation should be successful.
    ///
    /// Includes the number of commits behind.
    Behind(CommitPair, usize),
    /// Commit trees have diverged and either a force
    /// push or force pull is required to synchronize.
    Diverged(CommitPair),
}

impl fmt::Display for CommitRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(_) => {
                write!(f, "up to date")
            }
            Self::Behind(_, diff) => {
                write!(f, "{} change(s) behind remote: pull changes", diff)
            }
            Self::Ahead(_, diff) => {
                write!(f, "{} change(s) ahead of remote: push changes", diff)
            }
            Self::Diverged(_) => {
                write!(f, "local and remote have diverged: force push or force pull to synchronize trees")
            }
        }
    }
}

impl CommitRelationship {
    /// Get the pair of local and remote commit proofs.
    pub fn pair(&self) -> &CommitPair {
        match self {
            Self::Equal(pair) | Self::Diverged(pair) => pair,
            Self::Behind(pair, _) | Self::Ahead(pair, _) => pair,
        }
    }
}
