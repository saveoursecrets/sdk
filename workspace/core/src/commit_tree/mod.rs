//! Type for iterating and managing the commit trees for a vault.
use std::ops::Range;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use crate::{Error, Result};

mod proof;

#[cfg(not(target_arch = "wasm32"))]
mod integrity;

#[cfg(not(target_arch = "wasm32"))]
pub use integrity::{vault_commit_tree_file, wal_commit_tree_file};

pub use proof::{CommitHash, CommitPair, CommitProof, Comparison};

/// Compute the Sha256 hash of some data.
pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::hash(data)
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

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.tree.leaves_len()
    }

    /// Determine if this commit tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        let leaf_indices = indices.collect::<Vec<_>>();
        self.proof(&leaf_indices)
    }

    /// Get a proof for the given indices.
    pub fn proof(&self, leaf_indices: &[usize]) -> Result<CommitProof> {
        let root = self.root().ok_or(Error::NoRootCommit)?;
        let proof = self.tree.proof(leaf_indices);
        // Map the usize array to a Range, implies all the elements
        // are continuous, sparse indices are not supported
        //
        // Internally we use a range to represent the indices as these
        // proofs are sent over the network.
        let indices = if leaf_indices.is_empty() {
            0..0
        } else if leaf_indices.len() > 1 {
            leaf_indices[0]..leaf_indices[leaf_indices.len() - 1] + 1
        } else {
            leaf_indices[0]..leaf_indices[0] + 1
        };
        Ok(CommitProof(root, proof, self.len(), indices))
    }

    /// Compare this tree against another root hash and merkle proof.
    pub fn compare(&self, proof: CommitProof) -> Result<Comparison> {
        let CommitProof(other_root, proof, count, range) = proof;
        let root = self.root().ok_or(Error::NoRootCommit)?;
        if root == other_root {
            Ok(Comparison::Equal)
        } else if range.start < self.len() && range.end < self.len() {
            let leaves = self.tree.leaves().unwrap_or_default();
            let indices_to_prove = range.clone().collect::<Vec<_>>();
            let leaves_to_prove =
                range.map(|i| *leaves.get(i).unwrap()).collect::<Vec<_>>();
            if proof.verify(
                other_root,
                indices_to_prove.as_slice(),
                leaves_to_prove.as_slice(),
                count,
            ) {
                Ok(Comparison::Contains(indices_to_prove, leaves_to_prove))
            } else {
                Ok(Comparison::Unknown)
            }
        } else {
            Ok(Comparison::Unknown)
        }
    }

    /// Get the root hash of the underlying merkle tree.
    pub fn root(&self) -> Option<<Sha256 as Hasher>::Hash> {
        self.tree.root()
    }

    /// Get the root hash of the underlying merkle tree as hexadecimal.
    pub fn root_hex(&self) -> Option<String> {
        self.tree.root_hex()
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

    /// Create a commit tree from an existing vault.
    fn from_vault(vault: &Vault) -> CommitTree {
        let mut commit_tree = CommitTree::new();
        for (_, commit) in vault.commits() {
            commit_tree.tree.insert(commit.to_bytes());
        }
        commit_tree.tree.commit();
        commit_tree
    }

    fn mock_commit_tree() -> Result<CommitTree> {
        let (encryption_key, _, _) = mock_encryption_key()?;
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

        Ok(from_vault(&vault))
    }

    #[test]
    fn commit_tree_from_vault() -> Result<()> {
        let commit_tree = mock_commit_tree()?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }

    #[test]
    fn commit_proof_serde() -> Result<()> {
        let commit_tree = mock_commit_tree()?;
        let proof = commit_tree.head()?;

        let json = serde_json::to_string_pretty(&proof)?;
        let commit_proof: CommitProof = serde_json::from_str(&json)?;

        assert_eq!(proof.0, commit_proof.0);
        assert_eq!(proof.1.proof_hashes(), commit_proof.1.proof_hashes());
        assert_eq!(proof.2, commit_proof.2);
        assert_eq!(proof.3, commit_proof.3);

        Ok(())
    }
}
