//! Create and compare commits in an underlying merkle tree.
mod integrity;
mod proof;
mod tree;

/// Commit hash of zeroes.
pub const ZERO: [u8; 32] = [0u8; 32];

pub use integrity::{event_log_commit_tree_file, vault_commit_tree_file};
pub use proof::{CommitHash, CommitProof, Comparison};
pub use tree::CommitTree;

/// Commit state combines the last commit hash with
/// a commit proof.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CommitState(pub CommitHash, pub CommitProof);
