//! Traits and types for syncing between nodes.
use serde::{Serialize, Deserialize};
use sos_core::commit_tree::{CommitPair, CommitProof};
use std::fmt;

/// The relationship between a local and remote WAL file.
pub enum SyncStatus {
    /// Local and remote are equal.
    Equal(CommitPair),
    /// Local WAL is ahead of the remote.
    ///
    /// A push operation should be successful.
    Ahead(CommitPair, usize),
    /// Local WAL is behind the remote.
    ///
    /// A pull operation should be successful.
    Behind(CommitPair, usize),
    /// Commit trees have diverged and either a force
    /// push or force pull is required to synchronize.
    Diverged(CommitPair),
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(_) => {
                write!(f, "Up to date")
            }
            Self::Behind(_, diff) => {
                write!(f, "{} change(s) behind remote: pull changes.", diff)
            }
            Self::Ahead(_, diff) => {
                write!(f, "{} change(s) ahead of remote: push changes.", diff)
            }
            Self::Diverged(_) => {
                write!(f, "local and remote have diverged: force push or force pull to synchronize trees.")
            }
        }
    }
}

impl SyncStatus {
    /// Get the pair of local and remote commit proofs.
    pub fn pair(&self) -> &CommitPair {
        match self {
            Self::Equal(pair) | Self::Diverged(pair) => pair,
            Self::Behind(pair, _) | Self::Ahead(pair, _) => pair,
        }
    }
}

/// Enumerates the kind set after synchronization was attempted.
#[derive(Serialize, Deserialize)]
pub enum SyncKind {
    /// Local and remote are equal.
    Equal,
    /// Safe synchronization was made.
    Safe,
    /// Forced synchronization was performed.
    Force,
    /// Synchronization is not safe and a
    /// forceful attempt is required.
    Unsafe,
}

/// Information yielded after attempting synchronization.
#[derive(Serialize, Deserialize)]
pub struct SyncInfo {
    /// Local and remote proofs before synchronization.
    pub before: (CommitProof, CommitProof),
    /// Proof after synchronization.
    ///
    /// If the root hashes for local and remote are up to
    /// date this will be `None`.
    pub after: Option<CommitProof>,

    /// The status of the synchronization attempt.
    pub status: SyncKind,
}
