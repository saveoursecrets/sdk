use crate::{Error, Result};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

use super::{CommitHash, CommitProof, CommitState, Comparison};

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
        self.maybe_last_commit = Some(hash);
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
    pub fn leaves(&self) -> Option<Vec<<Sha256 as Hasher>::Hash>> {
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
                    Ok(Comparison::Contains(
                        indices_to_prove.to_vec(),
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

    /*
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
    */

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
