use crate::{Error, Result};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

use super::{CommitHash, CommitProof, CommitState, Comparison, TreeHash};

/// Encapsulates a Merkle tree and provides functions
/// for generating and comparing proofs.
#[derive(Default)]
pub struct CommitTree {
    tree: MerkleTree<Sha256>,
    maybe_last_commit: Option<TreeHash>,
    last_commit: Option<TreeHash>,
}

impl CommitTree {
    /// Create a new empty commit tree.
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<Sha256>::new(),
            maybe_last_commit: None,
            last_commit: None,
        }
    }

    /// Compute the Sha256 hash of some data.
    pub fn hash(data: &[u8]) -> TreeHash {
        Sha256::hash(data)
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.tree.leaves_len()
    }

    /// Determine if this commit tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a commit hash into the tree,
    pub fn insert(&mut self, hash: TreeHash) -> &mut Self {
        self.maybe_last_commit = Some(hash);
        self.tree.insert(hash);
        self
    }

    /// Append a collections of commit hashes to the tree.
    pub fn append(&mut self, hashes: &mut Vec<TreeHash>) -> &mut Self {
        self.maybe_last_commit = hashes.last().cloned();
        self.tree.append(hashes);
        self
    }

    /// Commit changes to the tree to compute the root.
    pub fn commit(&mut self) {
        self.tree.commit();
        if self.maybe_last_commit.is_some() {
            self.last_commit = self.maybe_last_commit.take();
        }
    }

    /// Revert changes to the tree.
    pub fn rollback(&mut self) {
        self.tree.rollback();
        self.maybe_last_commit = None;
        if let Some(leaves) = self.leaves() {
            self.last_commit = leaves.last().cloned();
        } else {
            self.last_commit = None;
        }
    }

    /// Leaves of the tree.
    pub fn leaves(&self) -> Option<Vec<TreeHash>> {
        self.tree.leaves()
    }

    /// Root hash and a proof of the last leaf node.
    pub fn head(&self) -> Result<CommitProof> {
        if self.is_empty() {
            return Err(Error::NoRootCommit);
        }
        self.proof(&[self.tree.leaves_len() - 1])
    }

    /// Proof for the given indices.
    pub fn proof(&self, leaf_indices: &[usize]) -> Result<CommitProof> {
        let root = self.root().ok_or(Error::NoRootCommit)?;
        let proof = self.tree.proof(leaf_indices);
        Ok(CommitProof {
            root,
            proof,
            length: self.len(),
            indices: leaf_indices.to_vec(),
        })
    }

    /// Compare this tree against another root hash and merkle proof.
    pub fn compare(&self, proof: &CommitProof) -> Result<Comparison> {
        let CommitProof {
            root: other_root,
            proof,
            length,
            indices: indices_to_prove,
        } = proof;
        let root = self.root().ok_or(Error::NoRootCommit)?;
        if &root == other_root {
            Ok(Comparison::Equal)
        } else {
            let leaves = self.tree.leaves().unwrap_or_default();
            let leaves_to_prove = indices_to_prove
                .into_iter()
                .filter_map(|i| leaves.get(*i).cloned())
                .collect::<Vec<_>>();
            if leaves_to_prove.len() == indices_to_prove.len() {
                if proof.verify(
                    other_root.into(),
                    indices_to_prove.as_slice(),
                    leaves_to_prove.as_slice(),
                    *length,
                ) {
                    Ok(Comparison::Contains(indices_to_prove.to_vec()))
                } else {
                    Ok(Comparison::Unknown)
                }
            } else {
                Ok(Comparison::Unknown)
            }
        }
    }

    /// Compute the first commit state.
    ///
    /// Must have at least one commit.
    pub fn first_commit(&self) -> Result<CommitState> {
        let leaves = self.tree.leaves().ok_or(Error::NoRootCommit)?;

        // Compute a proof for the first commit
        let leaf = *leaves.first().ok_or(Error::NoRootCommit)?;
        let leaves = vec![leaf];
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let proof = tree.proof(&[0]);
        let root = tree.root().map(CommitHash).ok_or(Error::NoRootCommit)?;
        let first_proof = CommitProof {
            root,
            proof,
            length: leaves.len(),
            indices: vec![0],
        };

        let first_commit = CommitHash(leaf);
        Ok(CommitState(first_commit, first_proof))
    }

    /// Last commit hash in the underlying merkle tree.
    pub fn last_commit(&self) -> Option<CommitHash> {
        self.last_commit.map(CommitHash)
    }

    /// Commit state of this tree.
    ///
    /// The tree must already have some commits.
    pub fn commit_state(&self) -> Result<CommitState> {
        let last_commit = self.last_commit().ok_or(Error::NoLastCommit)?;
        Ok(CommitState(last_commit, self.head()?))
    }

    /// Root hash of the underlying merkle tree.
    pub fn root(&self) -> Option<CommitHash> {
        self.tree.root().map(CommitHash)
    }

    /// Root hash of the underlying merkle tree as hexadecimal.
    pub fn root_hex(&self) -> Option<String> {
        self.tree.root().map(hex::encode)
    }

    /// Given a proof from another tree determine if this
    /// tree contains the other proof.
    pub fn contains(
        &self,
        other_proof: &CommitProof,
    ) -> Result<Option<CommitProof>> {
        Ok(match self.compare(other_proof)? {
            Comparison::Contains(indices) => Some(self.proof(&indices)?),
            _ => None,
        })
    }
}

#[cfg(debug_assertions)]
impl From<&crate::vault::Vault> for CommitTree {
    fn from(value: &crate::vault::Vault) -> Self {
        let mut commit_tree = CommitTree::new();
        for (_, commit) in value.commits() {
            commit_tree.tree.insert(commit.into());
        }
        commit_tree.tree.commit();
        commit_tree
    }
}
