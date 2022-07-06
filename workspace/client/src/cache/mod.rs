//! Types and traits for caching and synchronization.
use crate::Result;
use std::fmt;

use async_trait::async_trait;

use sos_core::{
    address::AddressStr,
    commit_tree::{CommitPair, CommitProof, CommitTree},
    events::{SyncEvent, WalEvent},
    secret::SecretRef,
    vault::Summary,
    wal::{
        file::WalFileRecord,
        snapshot::{SnapShot, SnapShotManager},
    },
    Gatekeeper,
};

use url::Url;

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

/// The status of a synchronization attempt.
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

/// Information yielded from a pull or a push.
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

/// Trait for types that cache vaults locally; supports a *current* view
/// into a selected vault and allows making changes to the currently
/// selected vault.
#[async_trait]
pub trait ClientCache {
    /// Get the server URL.
    fn server(&self) -> &Url;

    /// Get the address of the current user.
    fn address(&self) -> Result<AddressStr>;

    /// Get the vault summaries for this cache.
    fn vaults(&self) -> &[Summary];

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> &SnapShotManager;

    /// Take a snapshot of the WAL for the given vault.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

    /// Get the history for a WAL file.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(WalFileRecord, WalEvent<'_>)>>;

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Load the vault summaries from the remote server.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to find a summary in this cache.
    fn find_vault(&self, vault: &SecretRef) -> Option<&Summary>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<String>;

    /// Create a new vault.
    async fn create_vault(&mut self, name: String) -> Result<String>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Attempt to set the vault name on the remote server.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Get a comparison between a local WAL and remote WAL.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `SyncStatus`.
    async fn vault_status(
        &self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)>;

    /// Apply changes to a vault.
    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()>;

    /// Load a vault, unlock it and set it as the current vault.
    async fn open_vault(
        &mut self,
        summary: &Summary,
        password: &str,
    ) -> Result<()>;

    /// Get the current in-memory vault access.
    fn current(&self) -> Option<&Gatekeeper>;

    /// Get a mutable reference to the current in-memory vault access.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper>;

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    fn close_vault(&mut self);

    /// Get a reference to the commit tree for a WAL file.
    fn wal_tree(&self, summary: &Summary) -> Option<&CommitTree>;

    /// Download changes from the remote server.
    async fn pull(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo>;

    /// Upload changes to the remote server.
    async fn push(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo>;
}

mod disc;

pub use disc::FileCache;
