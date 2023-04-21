//! Create and compare commits in an underlying merkle tree.
mod proof;
mod tree;

#[cfg(not(target_arch = "wasm32"))]
mod integrity;

#[cfg(not(target_arch = "wasm32"))]
pub use integrity::{vault_commit_tree_file, wal_commit_tree_file};

pub use proof::{
    CommitHash, CommitPair, CommitProof, CommitRelationship, Comparison,
};
pub use tree::{CommitTree, MultiTree};
