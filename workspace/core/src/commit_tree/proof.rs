//! Types that encapsulate commit proofs and comparisons.
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Serialize,
};
use std::{fmt, ops::Range};

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};

/// Newtype for a 32 byte hash that provides a hexadecimal
/// display implementation.
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

/// A pair of commit proofs.
pub struct CommitPair {
    /// Commit proof for a local commit tree.
    pub local: CommitProof,
    /// Commit proof for a remote commit tree.
    pub remote: CommitProof,
}

/// Represents a root hash and a proof of certain nodes.
pub struct CommitProof(
    /// Root hash.
    pub <Sha256 as Hasher>::Hash,
    /// The merkle proof.
    pub MerkleProof<Sha256>,
    /// The length of the tree.
    pub usize,
    /// Range of indices.
    pub Range<usize>,
);

impl PartialEq for CommitProof {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
            && self.1.proof_hashes() == other.1.proof_hashes()
            && self.2 == other.2
            && self.3 == other.3
    }
}

impl Eq for CommitProof {}

impl Clone for CommitProof {
    fn clone(&self) -> Self {
        let hashes = self.1.proof_hashes().to_vec();
        CommitProof(
            self.0,
            MerkleProof::<Sha256>::new(hashes),
            self.2,
            self.3.clone(),
        )
    }
}

impl CommitProof {
    /// The root hash for the proof.
    pub fn root(&self) -> &<Sha256 as Hasher>::Hash {
        &self.0
    }

    /// The root hash for the proof as hexadecimal.
    pub fn root_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Number of leaves in the commit tree.
    pub fn len(&self) -> usize {
        self.2
    }

    /// Determine if this proof is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reduce this commit proof to it's root hash and leaves length.
    ///
    /// Sometimes we want to put a commit proof into an `Error`
    /// implementation but cannot due to the `MerkleProof` type so
    /// this reduces the proof to simpler error-safe types.
    pub fn reduce(self) -> (CommitHash, usize) {
        (CommitHash(self.0), self.2)
    }
}

impl Default for CommitProof {
    fn default() -> Self {
        Self([0; 32], MerkleProof::<Sha256>::new(vec![]), 0, 0..0)
    }
}

impl Encode for CommitProof {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(self.0)?;
        let proof_bytes = self.1.to_bytes();
        writer.write_u32(proof_bytes.len() as u32)?;
        writer.write_bytes(&proof_bytes)?;

        writer.write_u32(self.2 as u32)?;
        writer.write_u32(self.3.start as u32)?;
        writer.write_u32(self.3.end as u32)?;
        Ok(())
    }
}

impl Decode for CommitProof {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let root_hash: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        self.0 = root_hash;
        let length = reader.read_u32()?;
        let proof_bytes = reader.read_bytes(length as usize)?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(Box::from)?;

        self.1 = proof;
        self.2 = reader.read_u32()? as usize;
        let start = reader.read_u32()?;
        let end = reader.read_u32()?;

        // TODO: validate range start is <= range end

        self.3 = start as usize..end as usize;
        Ok(())
    }
}

impl fmt::Debug for CommitProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitProof")
            .field("root", &hex::encode(self.0))
            //.field("proofs", self.1.proof_hashes())
            .field("size", &self.2)
            .field("leaves", &self.3)
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
        let root_hash = hex::encode(self.0);
        tup.serialize_element(&root_hash)?;
        let hashes = self.1.proof_hashes();
        tup.serialize_element(hashes)?;
        tup.serialize_element(&self.2)?;
        tup.serialize_element(&self.3)?;
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
        let root_hash = hex::decode(&root_hash).map_err(de::Error::custom)?;
        let root_hash: [u8; 32] =
            root_hash.as_slice().try_into().map_err(de::Error::custom)?;
        let hashes: Vec<[u8; 32]> = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting sequence of proof hashes")
        })?;
        let size: usize = seq.next_element()?.ok_or_else(|| {
            de::Error::custom("expecting tree length usize")
        })?;
        let range: Range<usize> = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("expecting leaf node range"))?;
        Ok(CommitProof(
            root_hash,
            MerkleProof::new(hashes),
            size,
            range,
        ))
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
