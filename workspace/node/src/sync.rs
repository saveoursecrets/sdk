//! Traits and types for syncing between nodes.
use serde::{Deserialize, Serialize};
use sos_core::commit::CommitProof;

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
