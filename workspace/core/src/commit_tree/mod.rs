//! Type for iterating and managing the commit trees for a vault.
use serde_binary::{
    binary_rw::{BinaryReader, Endian, ReadStream, SeekStream},
    Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
};
use std::ops::Range;

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

use crate::{
    vault::{Header, Vault},
    Error, Result,
};

mod integrity;

pub use integrity::vault_commit_tree;
pub use integrity::wal_commit_tree;

/// Compute the Sha256 hash of some data.
pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::hash(data)
}

/// Represents a root hash and a proof of certain nodes.
//#[derive(Debug, Eq, PartialEq)]
pub struct CommitProof(
    pub <Sha256 as Hasher>::Hash,
    pub MerkleProof<Sha256>,
    pub usize,
    pub Range<usize>,
);

impl Clone for CommitProof {
    fn clone(&self) -> Self {
        let hashes = self
            .1
            .proof_hashes()
            .into_iter()
            .map(|h| *h)
            .collect::<Vec<_>>();
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
        hex::encode(&self.0)
    }

    /// Number of leaves in the commit tree.
    pub fn len(&self) -> usize {
        self.2
    }

    /// Reduce this commit proof to it's root hash and leaves length.
    pub fn reduce(self) -> ([u8; 32], usize) {
        (self.0, self.2)
    }
}

impl Default for CommitProof {
    fn default() -> Self {
        Self([0; 32], MerkleProof::<Sha256>::new(vec![]), 0, 0..0)
    }
}

impl Encode for CommitProof {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&self.0)?;
        let proof_bytes = self.1.to_bytes();
        ser.writer.write_u32(proof_bytes.len() as u32)?;
        ser.writer.write_bytes(&proof_bytes)?;

        ser.writer.write_u32(self.2 as u32)?;
        ser.writer.write_u32(self.3.start as u32)?;
        ser.writer.write_u32(self.3.end as u32)?;
        Ok(())
    }
}

impl Decode for CommitProof {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let root_hash: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;
        self.0 = root_hash;
        let length = de.reader.read_u32()?;
        let proof_bytes = de.reader.read_bytes(length as usize)?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(Box::from)?;

        self.1 = proof;
        self.2 = de.reader.read_u32()? as usize;
        let start = de.reader.read_u32()?;
        let end = de.reader.read_u32()?;

        // TODO: validate range start is <= range end

        self.3 = start as usize..end as usize;
        Ok(())
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

/// Encapsulates a merkle tree using a Sha256 hash function.
#[derive(Default)]
pub struct CommitTree {
    tree: MerkleTree<Sha256>,
}

impl CommitTree {
    /// Create a new empty commit tree.
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<Sha256>::new(),
        }
    }

    // TODO: move this to another module!
    /// Create a commit tree from an existing vault.
    pub fn from_vault(vault: &Vault) -> Self {
        let mut commit_tree = Self::new();
        for (_, commit) in vault.commits() {
            commit_tree.tree.insert(commit.to_bytes());
        }
        commit_tree.tree.commit();
        commit_tree
    }

    // TODO: move this to another module!
    /// Create a commit tree from a row iterator.
    pub fn from_iterator<'a>(it: &mut RowIterator<'a>) -> Result<Self> {
        let mut commit_tree = Self::new();
        for row_info in it {
            let row_info = row_info?;
            commit_tree.tree.insert(row_info.commit);
        }
        commit_tree.tree.commit();
        Ok(commit_tree)
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.tree.leaves_len()
    }

    /// Insert a commit hash into the tree,
    pub fn insert(&mut self, hash: <Sha256 as Hasher>::Hash) -> &mut Self {
        self.tree.insert(hash);
        self
    }

    /// Append a collections of commit hashes to the tree.
    pub fn append(
        &mut self,
        hashes: &mut Vec<<Sha256 as Hasher>::Hash>,
    ) -> &mut Self {
        self.tree.append(hashes);
        self
    }

    /// Commit changes to the tree to compute the root.
    pub fn commit(&mut self) {
        self.tree.commit()
    }

    /// Revert changes to the tree.
    pub fn rollback(&mut self) {
        self.tree.rollback()
    }

    /// Get the leaves of the tree.
    pub fn leaves(&self) -> Option<Vec<<Sha256 as Hasher>::Hash>> {
        self.tree.leaves()
    }

    /// Get the root hash and a proof of the last leaf node.
    pub fn head(&self) -> Result<CommitProof> {
        let range = self.tree.leaves_len() - 1..self.tree.leaves_len();
        self.proof_range(range)
    }

    /// Get a proof for the given range.
    pub fn proof_range(&self, indices: Range<usize>) -> Result<CommitProof> {
        let leaf_indices = indices.clone().map(|i| i).collect::<Vec<_>>();
        self.proof(&leaf_indices)
    }

    /// Get a proof for the given indices.
    pub fn proof(&self, leaf_indices: &[usize]) -> Result<CommitProof> {
        let root = self.root().ok_or(Error::NoRootCommit)?;
        let proof = self.tree.proof(&leaf_indices);
        // Map the usize array to a Range, implies all the elements
        // are continuous, sparse indices are not supported
        //
        // Internally we use a range to represent the indices as these
        // proofs are sent over the network.
        let indices = if leaf_indices.len() == 0 {
            0..0
        } else {
            if leaf_indices.len() > 1 {
                leaf_indices[0]..leaf_indices[leaf_indices.len() - 1] + 1
            } else {
                leaf_indices[0]..leaf_indices[0] + 1
            }
        };
        Ok(CommitProof(root, proof, self.len(), indices))
    }

    /// Compare this tree against another root hash and merkle proof.
    pub fn compare(&self, proof: CommitProof) -> Result<Comparison> {
        let CommitProof(other_root, proof, count, range) = proof;
        let root = self.root().ok_or(Error::NoRootCommit)?;
        if root == other_root {
            Ok(Comparison::Equal)
        } else {
            if range.start < self.len() && range.end < self.len() {
                let leaves = self.tree.leaves().unwrap_or_default();
                let indices_to_prove =
                    range.clone().map(|i| i).collect::<Vec<_>>();
                let leaves_to_prove = range
                    .map(|i| *leaves.get(i).unwrap())
                    .collect::<Vec<_>>();
                if proof.verify(
                    other_root,
                    indices_to_prove.as_slice(),
                    leaves_to_prove.as_slice(),
                    count,
                ) {
                    Ok(Comparison::Contains(
                        indices_to_prove,
                        leaves_to_prove,
                    ))
                } else {
                    Ok(Comparison::Unknown)
                }
            } else {
                Ok(Comparison::Unknown)
            }
        }
    }

    /// Get the root hash of the underlying merkle tree.
    pub fn root(&self) -> Option<<Sha256 as Hasher>::Hash> {
        self.tree.root()
    }
}

/// Refrerence to the identifier and commit for a row.
#[derive(Debug)]
pub struct RowInfo {
    /// Byte offset of the row.
    pub position: usize,
    /// The length of the row in bytes.
    pub length: u32,
    /// The bytes for the secret identifier.
    pub id: [u8; 16],
    /// The bytes for the commit hash.
    pub commit: [u8; 32],
    /// The byte range for the secret data.
    ///
    /// This is the absolute position in the underlying stream
    /// and gives the caller a chance to read in the secret value
    /// if it needs to.
    pub value: Range<usize>,
}

impl RowInfo {
    /// Read the bytes for the secret value into an owned buffer.
    pub fn read_value<'a>(
        &self,
        reader: &mut BinaryReader<'a>,
    ) -> Result<Vec<u8>> {
        let length = self.value.end - self.value.start;
        reader.seek(self.value.start)?;
        let value = reader.read_bytes(length)?;
        Ok(value)
    }

    /// Get the row identifier.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
}

/// Iterates a stream and yields identifiers and commits.
pub struct RowIterator<'a> {
    reader: BinaryReader<'a>,
    total_rows: u32,
    index: u32,
}

impl<'a> RowIterator<'a> {
    /// Create a new commit iterator that reads from the given stream.
    ///
    /// Expects a valid vault file and will return the vault header along
    /// with the iterator so that callers can access the vault file header information.
    pub fn new(stream: &'a mut impl ReadStream) -> Result<(Self, Header)> {
        let header = Header::read_header_stream(stream)?;
        let mut reader = BinaryReader::new(stream, Endian::Big);
        let total_rows = reader.read_u32()?;
        Ok((
            Self {
                reader,
                total_rows,
                index: 0,
            },
            header,
        ))
    }

    /// Get the expected number of rows in the stream.
    pub fn total_rows(&self) -> &u32 {
        &self.total_rows
    }

    /// Get the current iteration index.
    pub fn index(&self) -> &u32 {
        &self.index
    }

    fn read_row(&mut self) -> Result<RowInfo> {
        let position = self.reader.tell()?;
        let length = self.reader.read_u32()?;
        let id: [u8; 16] =
            self.reader.read_bytes(16)?.as_slice().try_into()?;
        let commit: [u8; 32] =
            self.reader.read_bytes(32)?.as_slice().try_into()?;

        let start = position + 52;
        let end = start + (length as usize - 48);

        let row_info = RowInfo {
            position,
            length,
            id,
            commit,
            value: start..end,
        };
        self.reader.seek(position + 4 + (length as usize))?;
        Ok(row_info)
    }
}

impl<'a> Iterator for RowIterator<'a> {
    type Item = Result<RowInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.total_rows {
            let row = self.read_row();
            self.index += 1;
            Some(row)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        events::SyncEvent,
        test_utils::*,
        vault::{Vault, VaultAccess, VaultEntry},
    };
    use anyhow::Result;

    #[test]
    fn commit_tree_from_vault() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let mut vault = mock_vault();
        let secrets = [
            ("Note one", "First note"),
            ("Note two", "Second note"),
            ("Note three", "Third note"),
        ];

        for (label, note) in secrets {
            let (_secret_meta, _secret_value, meta_bytes, secret_bytes) =
                mock_secret_note(label, note)?;
            let meta_aead = vault.encrypt(&encryption_key, &meta_bytes)?;
            let secret_aead =
                vault.encrypt(&encryption_key, &secret_bytes)?;
            let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
            let _secret_id = match vault
                .create(commit, VaultEntry(meta_aead, secret_aead))?
            {
                SyncEvent::CreateSecret(secret_id, _) => secret_id,
                _ => unreachable!(),
            };
        }

        let commit_tree = CommitTree::from_vault(&vault);
        assert!(commit_tree.root().is_some());

        Ok(())
    }
}
