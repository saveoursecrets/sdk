use crate::{Error, Result};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::{collections::HashMap, hash::Hash, ops::Range};

use super::{CommitPair, CommitProof, CommitRelationship, Comparison};

/// Encapsulates a Merkle tree and provides functions
/// for generating and comparing proofs.
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

    /// Compute the Sha256 hash of some data.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::hash(data)
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
        Ok(CommitProof {
            root,
            proof,
            length: self.len(),
            indices,
        })
    }

    /// Compare this tree against another root hash and merkle proof.
    pub fn compare(&self, proof: &CommitProof) -> Result<Comparison> {
        let CommitProof {
            root: other_root,
            proof,
            length,
            indices,
        } = proof;
        let root = self.root().ok_or(Error::NoRootCommit)?;
        if &root == other_root {
            Ok(Comparison::Equal)
        } else if indices.start < self.len() && indices.end <= self.len() {
            let leaves = self.tree.leaves().unwrap_or_default();
            let indices_to_prove = indices.clone().collect::<Vec<_>>();
            let leaves_to_prove = indices
                .clone()
                .map(|i| *leaves.get(i).unwrap())
                .collect::<Vec<_>>();
            if proof.verify(
                *other_root,
                indices_to_prove.as_slice(),
                leaves_to_prove.as_slice(),
                *length,
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

    /// Get the commit relationship from the proof in another tree and
    /// a match proof which indicates whether the current head proof
    /// of this tree is contained in the other tree.
    pub fn relationship(
        &self,
        other_proof: CommitProof,
        match_proof: Option<CommitProof>,
    ) -> Result<CommitRelationship> {
        let self_proof = self.head()?;
        let equals = self_proof.root() == other_proof.root();

        let pair = CommitPair {
            local: self_proof,
            remote: other_proof.clone(),
        };

        Ok(if equals {
            CommitRelationship::Equal(pair)
        } else {
            if let Some(_) = match_proof {
                let (diff, _) =
                    pair.remote.len().overflowing_sub(pair.local.len());
                CommitRelationship::Behind(pair, diff)
            } else {
                let comparison = self.compare(&other_proof)?;
                let is_ahead = match comparison {
                    Comparison::Contains(_, _) => true,
                    _ => false,
                };

                if is_ahead {
                    let (diff, _) =
                        pair.local.len().overflowing_sub(pair.remote.len());
                    CommitRelationship::Ahead(pair, diff)
                } else {
                    CommitRelationship::Diverged(pair)
                }
            }
        })
    }

    /// Given a proof from another tree determine if this
    /// tree contains the other proof.
    pub fn contains(
        &self,
        other_proof: &CommitProof,
    ) -> Result<Option<CommitProof>> {
        Ok(match self.compare(&other_proof)? {
            Comparison::Contains(indices, _leaves) => {
                Some(self.proof(&indices)?)
            }
            _ => None,
        })
    }
}

/// Multi tree allows comparison between multiple trees each 
/// represented by a unique identifier.
#[derive(Default)]
pub struct MultiTree<'a, K: Hash + Eq + PartialEq> {
    trees: HashMap<K, &'a CommitTree>,
}

impl<'a, K: Hash + Eq + PartialEq> MultiTree<'a, K> {
    /// Insert a tree reference into this multi tree.
    pub fn insert(&mut self, key: K, tree: &'a CommitTree) {
        self.trees.insert(key, tree);
    }

    /// Get the head proof for all trees.
    pub fn head(&'a self) -> Result<HashMap<&'a K, CommitProof>> {
        let mut proofs = HashMap::new();
        for (id, tree) in self.trees.iter() {
            proofs.insert(id, tree.head()?);
        }
        Ok(proofs)
    }

    /// Determine if each of the other proofs is contained in
    /// each of the trees in this multi tree.
    pub fn contains(
        &'a self,
        other: &HashMap<&'a K, CommitProof>,
    ) -> Result<HashMap<&'a K, Option<CommitProof>>> {
        let mut matches = HashMap::new();
        for (id, tree) in self.trees.iter() {
            if let Some(proof) = other.get(id) {
                matches.insert(id, tree.contains(proof)?);
            } else {
                matches.insert(id, None);
            }
        }
        Ok(matches)
    }

    /// Get the relationship between two multi trees.
    pub fn relationship(
        &'a self,
        proofs: HashMap<&'a K, CommitProof>,
        matches: HashMap<&'a K, Option<CommitProof>>,
    ) -> Result<HashMap<&'a K, CommitRelationship>> {
        let mut relationships = HashMap::new();
        for (id, tree) in self.trees.iter() {
            if let (Some(proof), Some(match_proof)) = (proofs.get(id), matches.get(id)) {
                //matches.insert(id, tree.contains(proof)?);
                //todo!();
                relationships.insert(id, tree.relationship(proof.clone(), match_proof.clone())?);
            }
        }
        Ok(relationships)
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
    use uuid::Uuid;

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

        assert_eq!(proof.root, commit_proof.root);
        assert_eq!(
            proof.proof.proof_hashes(),
            commit_proof.proof.proof_hashes()
        );
        assert_eq!(proof.length, commit_proof.length);
        assert_eq!(proof.indices, commit_proof.indices);

        Ok(())
    }

    #[test]
    fn commit_proof_compare() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let mut tree1 = CommitTree::new();
        tree1.insert(hash1);
        tree1.commit();

        let mut tree2 = CommitTree::new();
        tree2.insert(hash1);
        tree2.commit();

        let mut tree3 = CommitTree::new();
        tree3.insert(hash3);
        tree3.commit();

        assert!(tree1.root().is_some());
        assert!(tree2.root().is_some());

        assert_eq!(tree1.root(), tree2.root());

        let proof = tree1.proof(&[0])?;
        let comparison = tree2.compare(&proof)?;

        assert_eq!(Comparison::Equal, comparison);

        // Add another hash
        tree2.insert(hash2);
        tree2.commit();

        assert_ne!(tree1.root(), tree2.root());

        let proof = tree1.proof(&[0])?;
        let comparison = tree2.compare(&proof)?;
        assert!(matches!(comparison, Comparison::Contains(_, _)));

        let proof = tree2.proof(&[0])?;
        let comparison = tree1.compare(&proof)?;
        assert!(matches!(comparison, Comparison::Contains(_, _)));

        // Completely different trees
        let proof = tree1.proof(&[0])?;
        let comparison = tree3.compare(&proof)?;
        assert!(matches!(comparison, Comparison::Unknown));

        // Completely different trees
        let proof = tree3.proof(&[0])?;
        let comparison = tree2.compare(&proof)?;
        assert!(matches!(comparison, Comparison::Unknown));

        Ok(())
    }

    #[test]
    fn commit_proof_relationship_equal() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");

        let mut local = CommitTree::new();
        local.insert(hash1);
        local.commit();

        let mut remote = CommitTree::new();
        remote.insert(hash1);
        remote.commit();

        let local_proof = local.head()?;

        // Local sends proof to remote and remote indicates
        // if proof is contained in the remote tree.
        //
        // Remote replies with it's latest head proof
        // and the optional match proof.
        let match_proof = remote.contains(&local_proof)?;
        let remote_proof = remote.head()?;

        // Local can now determine the relationship between the two trees
        let relationship = local.relationship(remote_proof, match_proof)?;

        assert!(matches!(relationship, CommitRelationship::Equal(_)));

        Ok(())
    }

    #[test]
    fn commit_proof_relationship_diverged() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");

        let mut local = CommitTree::new();
        local.insert(hash1);
        local.commit();

        let mut remote = CommitTree::new();
        remote.insert(hash2);
        remote.commit();

        let local_proof = local.head()?;

        // Local sends proof to remote and remote indicates
        // if proof is contained in the remote tree.
        //
        // Remote replies with it's latest head proof
        // and the optional match proof.
        let match_proof = remote.contains(&local_proof)?;
        let remote_proof = remote.head()?;

        // Local can now determine the relationship between the two trees
        let relationship = local.relationship(remote_proof, match_proof)?;

        assert!(matches!(relationship, CommitRelationship::Diverged(_)));

        Ok(())
    }

    #[test]
    fn commit_proof_relationship_behind() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");

        let mut local = CommitTree::new();
        local.insert(hash1);
        local.commit();

        let mut remote = CommitTree::new();
        remote.insert(hash1);
        remote.insert(hash2);
        remote.commit();

        let local_proof = local.head()?;

        // Local sends proof to remote and remote indicates
        // if proof is contained in the remote tree.
        //
        // Remote replies with it's latest head proof
        // and the optional match proof.
        let match_proof = remote.contains(&local_proof)?;
        let remote_proof = remote.head()?;

        // Local can now determine the relationship between the two trees
        let relationship = local.relationship(remote_proof, match_proof)?;

        assert!(matches!(relationship, CommitRelationship::Behind(_, _)));

        Ok(())
    }

    #[test]
    fn commit_proof_relationship_ahead() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");

        let mut local = CommitTree::new();
        local.insert(hash1);
        local.insert(hash2);
        local.commit();

        let mut remote = CommitTree::new();
        remote.insert(hash1);
        remote.commit();

        let local_proof = local.head()?;

        // Local sends proof to remote and remote indicates
        // if proof is contained in the remote tree.
        //
        // Remote replies with it's latest head proof
        // and the optional match proof.
        let match_proof = remote.contains(&local_proof)?;
        let remote_proof = remote.head()?;

        // Local can now determine the relationship between the two trees
        let relationship = local.relationship(remote_proof, match_proof)?;

        assert!(matches!(relationship, CommitRelationship::Ahead(_, _)));

        Ok(())
    }

    #[test]
    fn commit_multi_equal() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();

        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();

        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        local_tree2.commit();

        let mut local: MultiTree<Uuid> = Default::default();
        local.insert(tree_id1, &local_tree1);
        local.insert(tree_id2, &local_tree2);

        let mut remote_tree1 = CommitTree::new();
        remote_tree1.insert(hash1);
        remote_tree1.commit();

        let mut remote_tree2 = CommitTree::new();
        remote_tree2.insert(hash2);
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let local_proofs = local.head()?;
        let match_proofs = remote.contains(&local_proofs)?;
        let remote_proofs = remote.head()?;

        let mut relationships =
            local.relationship(remote_proofs, match_proofs)?;

        assert!(
            matches!(
                relationships.remove(&tree_id1).unwrap(),
                CommitRelationship::Equal(_)
            )
        );

        assert!(
            matches!(
                relationships.remove(&tree_id2).unwrap(),
                CommitRelationship::Equal(_)
            )
        );

        Ok(())
    }
}
