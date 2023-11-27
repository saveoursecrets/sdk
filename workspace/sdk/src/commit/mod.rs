//! Create and compare commits in an underlying merkle tree.
use serde::{Deserialize, Serialize};

mod integrity;
mod proof;
mod tree;

pub use integrity::{event_log_commit_tree_file, vault_commit_tree_file};

pub use proof::{
    CommitHash, CommitPair, CommitProof, CommitRelationship, Comparison,
};
pub use tree::CommitTree;

/// Commit state combines the last commit hash with
/// a commit proof.
pub type CommitState = (CommitHash, CommitProof);
