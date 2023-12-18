use crate::{Error, Result};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::ops::Range;

use super::{
    CommitHash, CommitPair, CommitProof, CommitRelationship, CommitState,
    Comparison,
};

/// Encapsulates a Merkle tree and provides functions
/// for generating and comparing proofs.
#[derive(Default)]
pub struct CommitTree {
    tree: MerkleTree<Sha256>,
    maybe_last_commit: Option<<Sha256 as Hasher>::Hash>,
    last_commit: Option<<Sha256 as Hasher>::Hash>,
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
    pub fn hash(data: &[u8]) -> [u8; 32] {
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
    pub fn insert(&mut self, hash: <Sha256 as Hasher>::Hash) -> &mut Self {
        self.maybe_last_commit = Some(hash.clone());
        self.tree.insert(hash);
        self
    }

    /// Append a collections of commit hashes to the tree.
    pub fn append(
        &mut self,
        hashes: &mut Vec<<Sha256 as Hasher>::Hash>,
    ) -> &mut Self {
        self.maybe_last_commit = hashes.last().cloned();
        self.tree.append(hashes);
        self
    }

    /// Commit changes to the tree to compute the root.
    pub fn commit(&mut self) {
        self.tree.commit();
        self.last_commit = self.maybe_last_commit.take();
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
    pub fn leaves(&self) -> Option<Vec<<Sha256 as Hasher>::Hash>> {
        self.tree.leaves()
    }

    /// Root hash and a proof of the last leaf node.
    pub fn head(&self) -> Result<CommitProof> {
        if self.is_empty() {
            return Err(Error::NoRootCommit);
        }
        let range = self.tree.leaves_len() - 1..self.tree.leaves_len();
        self.proof_range(range)
    }

    /// Get a proof up to a particular commit.
    pub fn proof_at(&self, commit: &CommitHash) -> Result<CommitProof> {
        let mut leaves = self.tree.leaves().unwrap_or_default();
        let position = leaves.iter().position(|leaf| leaf == commit.as_ref());
        if let Some(position) = position {
            if position < leaves.len() - 1 {
                leaves.truncate(position + 1);
                let partial = MerkleTree::from_leaves(&leaves);
                let indices = 0..leaves.len();
                let leaf_indices = indices.clone().collect::<Vec<_>>();
                let proof = partial.proof(&leaf_indices);
                let root = partial
                    .root()
                    .map(CommitHash)
                    .ok_or(Error::NoRootCommit)?;
                Ok(CommitProof {
                    root,
                    proof,
                    length: leaves.len(),
                    indices,
                })
            } else {
                self.head()
            }
        } else {
            Err(Error::NoRootCommit)
        }
    }

    /// Proof for the given range.
    pub fn proof_range(&self, indices: Range<usize>) -> Result<CommitProof> {
        let leaf_indices = indices.collect::<Vec<_>>();
        self.proof(&leaf_indices)
    }

    /// Proof for the given indices.
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
                other_root.into(),
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

    /// Compute the first commit state.
    ///
    /// Must have at least one commit.
    pub fn first_commit(&self) -> Result<CommitState> {
        let leaves = self.tree.leaves().ok_or(Error::NoRootCommit)?;
        let first_commit =
            CommitHash(*leaves.first().ok_or(Error::NoRootCommit)?);
        let first_proof = self.proof_at(&first_commit)?;
        Ok((first_commit, first_proof))
    }

    /// Last commit hash in the underlying merkle tree.
    pub fn last_commit(&self) -> Option<CommitHash> {
        self.last_commit.map(CommitHash)
    }

    /// Commit state of this tree.
    ///
    /// The tree must already have some commits.
    pub fn commit_state(&self) -> Result<CommitState> {
        let last_commit = self.last_commit().ok_or(Error::NoRootCommit)?;
        Ok((last_commit, self.head()?))
    }

    /// Root hash of the underlying merkle tree.
    pub fn root(&self) -> Option<CommitHash> {
        self.tree.root().map(CommitHash)
    }

    /// Commit relationship between the proof in another tree and
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
        } else if match_proof.is_some() {
            let (diff, _) =
                pair.remote.len().overflowing_sub(pair.local.len());
            CommitRelationship::Behind(pair, diff)
        } else {
            let comparison = self.compare(&other_proof)?;
            let is_ahead = matches!(comparison, Comparison::Contains(_, _));

            if is_ahead {
                let (diff, _) =
                    pair.local.len().overflowing_sub(pair.remote.len());
                CommitRelationship::Ahead(pair, diff)
            } else {
                CommitRelationship::Diverged(pair)
            }
        })
    }

    /// Given a proof from another tree determine if this
    /// tree contains the other proof.
    pub fn contains(
        &self,
        other_proof: &CommitProof,
    ) -> Result<Option<CommitProof>> {
        Ok(match self.compare(other_proof)? {
            Comparison::Contains(indices, _leaves) => {
                Some(self.proof(&indices)?)
            }
            _ => None,
        })
    }
}

/*
/// Multi tree allows comparison between multiple trees each
/// represented by a unique identifier.
///
/// The identifier for each tree would be the vault identifier (UUID).
#[derive(Default)]
pub struct MultiTree<'a, K>
where
    K: Hash + Eq + PartialEq + Copy,
{
    trees: HashMap<K, &'a CommitTree>,
}

impl<'a, K> MultiTree<'a, K>
where
    K: Hash + Eq + PartialEq + Copy,
{
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
        proofs: &HashMap<&'a K, CommitProof>,
        matches: &HashMap<&'a K, Option<CommitProof>>,
    ) -> Result<HashMap<&'a K, CommitRelationship>> {
        let mut relationships = HashMap::new();
        for (id, tree) in self.trees.iter() {
            if let (Some(proof), Some(match_proof)) =
                (proofs.get(id), matches.get(id))
            {
                relationships.insert(
                    id,
                    tree.relationship(proof.clone(), match_proof.clone())?,
                );
            }
        }
        Ok(relationships)
    }
}
*/

/*
/// Node tree represents multi trees from different nodes
/// combined so that a node can determine which actions to
/// take for a sync operation.
///
/// The identifier for each node would typically be the peer id
/// which for trusted devices is the public key of the
/// device signing key.
pub struct NodeTree<'a, I, K>
where
    I: Hash + Eq + PartialEq + Copy,
    K: Hash + Eq + PartialEq + Copy,
{
    /// Identifier of this node.
    id: I,
    /// Tree for this node.
    tree: &'a MultiTree<'a, K>,
    /// Trees for other nodes.
    nodes: HashMap<I, &'a MultiTree<'a, K>>,
}

impl<'a, I, K> NodeTree<'a, I, K>
where
    I: Hash + Eq + PartialEq + Copy,
    K: Hash + Eq + PartialEq + Copy,
{
    /// Create a new node tree.
    pub fn new(id: I, tree: &'a MultiTree<'a, K>) -> Self {
        Self {
            id,
            tree,
            nodes: HashMap::new(),
        }
    }

    /// Insert a multi tree into this node.
    pub fn insert(&mut self, key: I, tree: &'a MultiTree<'a, K>) {
        self.nodes.insert(key, tree);
    }

    /// Compute the sync operations from this node tree.
    pub fn compute(
        &self,
        matches: HashMap<&'a I, HashMap<&'a K, Option<CommitProof>>>,
    ) -> Result<HashSet<Operation<I, K>>> {
        let mut ops = HashSet::new();

        for (node_id, tree) in self.nodes.iter() {
            if let Some(matches) = matches.get(node_id) {
                let proof = tree.head()?;
                let relationships =
                    self.tree.relationship(&proof, matches)?;
                for (id, relationship) in relationships {
                    match relationship {
                        CommitRelationship::Ahead(commit, difference) => {
                            ops.insert(Operation::Push {
                                local: self.id,
                                remote: *node_id,
                                id: *id,
                                commit,
                                difference,
                            });
                        }
                        CommitRelationship::Behind(commit, difference) => {
                            ops.insert(Operation::Pull {
                                local: self.id,
                                remote: *node_id,
                                id: *id,
                                commit,
                                difference,
                            });
                        }
                        CommitRelationship::Diverged(commit) => {
                            ops.insert(Operation::Conflict {
                                local: self.id,
                                remote: *node_id,
                                id: *id,
                                commit,
                            });
                        }
                        CommitRelationship::Equal(_) => {}
                    }
                }
            }
        }

        Ok(ops)
    }
}
*/

/*
/// Operation that can be made to sync between two peers.
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum Operation<I, K>
where
    I: Hash + Eq + PartialEq,
    K: Hash + Eq + PartialEq,
{
    /// Push to a remote peer.
    Push {
        /// Identifier of the peer to push from.
        local: I,
        /// Identifier of the peer to push to.
        remote: I,
        /// Identifier of the vault to operate on.
        id: K,
        /// Commit information.
        commit: CommitPair,
        /// Number of commits difference.
        difference: usize,
    },
    /// Pull from a remote peer.
    Pull {
        /// Identifier of the peer to pull to.
        local: I,
        /// Identifier of the peer to pull from.
        remote: I,
        /// Identifier of the vault to operate on.
        id: K,
        /// Commit information.
        commit: CommitPair,
        /// Number of commits difference.
        difference: usize,
    },
    /// Trees have diverged so we have a conflict that
    /// may be resolvable with a force push or force pull.
    ///
    /// Requires user intervention to decide.
    Conflict {
        /// Identifier of the local peer.
        local: I,
        /// Identifier of the remote peer.
        remote: I,
        /// Identifier of the vault to operate on.
        id: K,
        /// Commit information.
        commit: CommitPair,
    },
}
*/

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        events::WriteEvent,
        test_utils::*,
        vault::{Vault, VaultAccess, VaultBuilder, VaultEntry},
    };
    use anyhow::Result;

    /// Create a commit tree from an existing vault using the
    /// hashes of the encrypted data that are used to verify
    /// the integrity of each vault entry.
    fn from_vault(vault: &Vault) -> CommitTree {
        let mut commit_tree = CommitTree::new();
        for (_, commit) in vault.commits() {
            commit_tree.tree.insert(commit.to_bytes());
        }
        commit_tree.tree.commit();
        commit_tree
    }

    async fn mock_commit_tree() -> Result<CommitTree> {
        let (encryption_key, _, passphrase) = mock_encryption_key()?;
        let mut vault =
            VaultBuilder::new().password(passphrase, None).await?;

        let secrets = [
            ("Note one", "First note"),
            ("Note two", "Second note"),
            ("Note three", "Third note"),
        ];

        for (label, note) in secrets {
            let (_secret_meta, _secret_value, meta_bytes, secret_bytes) =
                mock_secret_note(label, note).await?;
            let meta_aead =
                vault.encrypt(&encryption_key, &meta_bytes).await?;
            let secret_aead =
                vault.encrypt(&encryption_key, &secret_bytes).await?;
            let (commit, _) =
                Vault::commit_hash(&meta_aead, &secret_aead).await?;
            let _secret_id = match vault
                .create(commit, VaultEntry(meta_aead, secret_aead))
                .await?
            {
                WriteEvent::CreateSecret(secret_id, _) => secret_id,
                _ => unreachable!(),
            };
        }

        Ok(from_vault(&vault))
    }

    #[tokio::test]
    async fn commit_tree_from_vault() -> Result<()> {
        let commit_tree = mock_commit_tree().await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn commit_proof_serde() -> Result<()> {
        let commit_tree = mock_commit_tree().await?;
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

    /*
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
            local.relationship(&remote_proofs, &match_proofs)?;

        assert!(matches!(
            relationships.remove(&tree_id1).unwrap(),
            CommitRelationship::Equal(_)
        ));

        assert!(matches!(
            relationships.remove(&tree_id2).unwrap(),
            CommitRelationship::Equal(_)
        ));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_multi_ahead() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();

        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();

        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        local_tree2.insert(hash3); // Makes this tree ahead
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
            local.relationship(&remote_proofs, &match_proofs)?;

        assert!(matches!(
            relationships.remove(&tree_id1).unwrap(),
            CommitRelationship::Equal(_)
        ));

        assert!(matches!(
            relationships.remove(&tree_id2).unwrap(),
            CommitRelationship::Ahead(_, _)
        ));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_multi_behind() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

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
        remote_tree2.insert(hash3); // Makes this tree ahead
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let local_proofs = local.head()?;
        let match_proofs = remote.contains(&local_proofs)?;
        let remote_proofs = remote.head()?;

        let mut relationships =
            local.relationship(&remote_proofs, &match_proofs)?;

        assert!(matches!(
            relationships.remove(&tree_id1).unwrap(),
            CommitRelationship::Equal(_)
        ));

        assert!(matches!(
            relationships.remove(&tree_id2).unwrap(),
            CommitRelationship::Behind(_, _)
        ));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_multi_diverged() -> Result<()> {
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

        // Flip the hashes so the trees are diverged
        let mut remote_tree1 = CommitTree::new();
        remote_tree1.insert(hash2);
        remote_tree1.commit();

        let mut remote_tree2 = CommitTree::new();
        remote_tree2.insert(hash1);
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let local_proofs = local.head()?;
        let match_proofs = remote.contains(&local_proofs)?;
        let remote_proofs = remote.head()?;

        let mut relationships =
            local.relationship(&remote_proofs, &match_proofs)?;

        assert!(matches!(
            relationships.remove(&tree_id1).unwrap(),
            CommitRelationship::Diverged(_)
        ));

        assert!(matches!(
            relationships.remove(&tree_id2).unwrap(),
            CommitRelationship::Diverged(_)
        ));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_equal() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

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

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let local_head = local.head()?;
        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert!(operations.is_empty());

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_push() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();

        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();

        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        local_tree2.insert(hash3); // Puts the local tree ahead of remote
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

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut remote_head = remote.head()?;

        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert_eq!(1, operations.len());

        let push = Operation::Push {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id2).unwrap(),
                remote: remote_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&push));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_pull() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

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
        remote_tree2.insert(hash3); // Puts the remote tree ahead of local
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut remote_head = remote.head()?;

        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert_eq!(1, operations.len());

        let pull = Operation::Pull {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id2).unwrap(),
                remote: remote_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&pull));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_conflict() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

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
        remote_tree2.insert(hash3); // Diverges this tree from local
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut remote_head = remote.head()?;

        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert_eq!(1, operations.len());

        let conflict = Operation::Conflict {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            commit: CommitPair {
                local: local_head.remove(&tree_id2).unwrap(),
                remote: remote_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&conflict));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_pull_push() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();

        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();

        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        local_tree2.insert(hash3); // Puts the local tree ahead of remote
        local_tree2.commit();

        let mut local: MultiTree<Uuid> = Default::default();
        local.insert(tree_id1, &local_tree1);
        local.insert(tree_id2, &local_tree2);

        let mut remote_tree1 = CommitTree::new();
        remote_tree1.insert(hash1);
        remote_tree1.insert(hash3); // Puts the remote tree ahead of local
        remote_tree1.commit();

        let mut remote_tree2 = CommitTree::new();
        remote_tree2.insert(hash2);
        remote_tree2.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut remote_head = remote.head()?;

        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert_eq!(2, operations.len());

        let push = Operation::Push {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id2).unwrap(),
                remote: remote_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&push));

        let pull = Operation::Pull {
            local: node_id1,
            remote: node_id2,
            id: tree_id1,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id1).unwrap(),
                remote: remote_head.remove(&tree_id1).unwrap(),
            },
        };
        assert!(operations.contains(&pull));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_node_pull_push_conflict() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();
        let tree_id3 = Uuid::new_v4();

        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();

        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        local_tree2.insert(hash3); // Puts the local tree ahead of remote
        local_tree2.commit();

        let mut local_tree3 = CommitTree::new();
        local_tree3.insert(hash1);
        local_tree3.commit();

        let mut local: MultiTree<Uuid> = Default::default();
        local.insert(tree_id1, &local_tree1);
        local.insert(tree_id2, &local_tree2);
        local.insert(tree_id3, &local_tree3);

        let mut remote_tree1 = CommitTree::new();
        remote_tree1.insert(hash1);
        remote_tree1.insert(hash3); // Puts the remote tree ahead of local
        remote_tree1.commit();

        let mut remote_tree2 = CommitTree::new();
        remote_tree2.insert(hash2);
        remote_tree2.commit();

        let mut remote_tree3 = CommitTree::new();
        remote_tree3.insert(hash2); // Conflict on this tree
        remote_tree3.commit();

        let mut remote: MultiTree<Uuid> = Default::default();
        remote.insert(tree_id1, &remote_tree1);
        remote.insert(tree_id2, &remote_tree2);
        remote.insert(tree_id3, &remote_tree3);

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut remote_head = remote.head()?;

        node.insert(node_id2, &remote);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, remote.contains(&local_head)?);

        let operations = node.compute(matches)?;
        assert_eq!(3, operations.len());

        let push = Operation::Push {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id2).unwrap(),
                remote: remote_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&push));

        let pull = Operation::Pull {
            local: node_id1,
            remote: node_id2,
            id: tree_id1,
            difference: 1,
            commit: CommitPair {
                local: local_head.remove(&tree_id1).unwrap(),
                remote: remote_head.remove(&tree_id1).unwrap(),
            },
        };
        assert!(operations.contains(&pull));

        let conflict = Operation::Conflict {
            local: node_id1,
            remote: node_id2,
            id: tree_id3,
            commit: CommitPair {
                local: local_head.remove(&tree_id3).unwrap(),
                remote: remote_head.remove(&tree_id3).unwrap(),
            },
        };
        assert!(operations.contains(&conflict));

        Ok(())
    }
    */

    /*
    #[test]
    fn commit_multi_node() -> Result<()> {
        let hash1 = CommitTree::hash(b"hello");
        let hash2 = CommitTree::hash(b"world");
        let hash3 = CommitTree::hash(b"goodbye");

        let node_id1 = Uuid::new_v4();
        let node_id2 = Uuid::new_v4();
        let node_id3 = Uuid::new_v4();

        let tree_id1 = Uuid::new_v4();
        let tree_id2 = Uuid::new_v4();
        let tree_id3 = Uuid::new_v4();

        // Node 1 (local)
        let mut local_tree1 = CommitTree::new();
        local_tree1.insert(hash1);
        local_tree1.commit();
        let mut local_tree2 = CommitTree::new();
        local_tree2.insert(hash2);
        // Puts the local tree ahead of remotes (node 2 and node 3)
        local_tree2.insert(hash3);
        local_tree2.commit();
        let mut local_tree3 = CommitTree::new();
        local_tree3.insert(hash3);
        local_tree3.commit();

        let mut local: MultiTree<Uuid> = Default::default();
        local.insert(tree_id1, &local_tree1);
        local.insert(tree_id2, &local_tree2);
        local.insert(tree_id3, &local_tree3);

        // Node 2
        let mut node2_tree1 = CommitTree::new();
        node2_tree1.insert(hash1);
        // Puts the remote tree ahead of local (node 1)
        node2_tree1.insert(hash3);
        node2_tree1.commit();
        let mut node2_tree2 = CommitTree::new();
        node2_tree2.insert(hash2);
        node2_tree2.commit();
        let mut node2_tree3 = CommitTree::new();
        node2_tree3.insert(hash2); // Conflict on this tree
        node2_tree3.commit();

        let mut node2: MultiTree<Uuid> = Default::default();
        node2.insert(tree_id1, &node2_tree1);
        node2.insert(tree_id2, &node2_tree2);
        node2.insert(tree_id3, &node2_tree3);

        // Node 3
        let mut node3_tree1 = CommitTree::new();
        node3_tree1.insert(hash1);
        node3_tree1.commit();
        let mut node3_tree2 = CommitTree::new();
        node3_tree2.insert(hash2);
        node3_tree2.commit();
        let mut node3_tree3 = CommitTree::new();
        node3_tree3.insert(hash3);
        node3_tree3.commit();

        let mut node3: MultiTree<Uuid> = Default::default();
        node3.insert(tree_id1, &node3_tree1);
        node3.insert(tree_id2, &node3_tree2);
        node3.insert(tree_id3, &node3_tree3);

        let mut node: NodeTree<Uuid, Uuid> = NodeTree::new(node_id1, &local);

        let mut local_head = local.head()?;
        let mut node2_head = node2.head()?;
        let mut node3_head = node3.head()?;

        node.insert(node_id2, &node2);
        node.insert(node_id3, &node3);

        let mut matches = HashMap::new();
        matches.insert(&node_id2, node2.contains(&local_head)?);
        matches.insert(&node_id3, node3.contains(&local_head)?);

        let operations = node.compute(matches)?;

        // Expects conflict, pull and two pushes
        let conflict = Operation::Conflict {
            local: node_id1,
            remote: node_id2,
            id: tree_id3,
            commit: CommitPair {
                local: local_head.remove(&tree_id3).unwrap(),
                remote: node2_head.remove(&tree_id3).unwrap(),
            },
        };
        assert!(operations.contains(&conflict));

        let node2_push = Operation::Push {
            local: node_id1,
            remote: node_id2,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.get(&tree_id2).cloned().unwrap(),
                remote: node2_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&node2_push));

        let node3_push = Operation::Push {
            local: node_id1,
            remote: node_id3,
            id: tree_id2,
            difference: 1,
            commit: CommitPair {
                local: local_head.get(&tree_id2).cloned().unwrap(),
                remote: node3_head.remove(&tree_id2).unwrap(),
            },
        };
        assert!(operations.contains(&node3_push));

        let pull = Operation::Pull {
            local: node_id1,
            remote: node_id2,
            id: tree_id1,
            difference: 1,
            commit: CommitPair {
                local: local_head.get(&tree_id1).cloned().unwrap(),
                remote: node2_head.remove(&tree_id1).unwrap(),
            },
        };
        assert!(operations.contains(&pull));

        Ok(())
    }
    */
}
