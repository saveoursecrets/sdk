//! Create and compare commits in an underlying merkle tree.
mod proof;
mod tree;

use rs_merkle::{algorithms::Sha256, Hasher};

/// Type for an Sha256 commit tree hash.
pub type TreeHash = <Sha256 as Hasher>::Hash;

/// Commit hash of zeroes.
pub const ZERO: TreeHash = [0u8; 32];

pub use proof::{CommitHash, CommitProof, Comparison};
pub use tree::CommitTree;

/// Commit state combines the last commit hash with
/// a commit proof.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CommitState(pub CommitHash, pub CommitProof);
