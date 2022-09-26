//! Storage provider trait.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitProof, CommitTree, Comparison},
    constants::{PATCH_EXT, WAL_EXT, WAL_IDENTITY},
    crypto::secret_key::SecretKey,
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    generate_passphrase,
    secret::SecretRef,
    signer::BoxedSigner,
    vault::{Header, Summary, Vault},
    wal::{
        memory::WalMemory,
        reducer::WalReducer,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, CommitHash, FileIdentity, Gatekeeper, PatchMemory,
    PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{constants::WAL_DELETED_EXT, wal::file::WalFile, PatchFile};

#[cfg(not(target_arch = "wasm32"))]
use std::{io::Write, path::Path};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

use crate::{
    client::node_state::NodeState,
    sync::{SyncInfo, SyncKind, SyncStatus},
};

/// Trait for storage providers.
#[async_trait]
pub trait StorageProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the state for this storage provider.
    fn state(&self) -> &NodeState;

    /// Get the vault summaries for this storage.
    fn vaults(&self) -> &[Summary];

    /// Get the current in-memory vault access.
    fn current(&self) -> Option<&Gatekeeper>;

    /// Get a mutable reference to the current in-memory vault access.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper>;

    /// Get the history of events for a vault.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>>;

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> Result<SecretString>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Load a vault, unlock it and set it as the current vault.
    fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()>;

    /// Close the currently selected vault.
    fn close_vault(&mut self);

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;
}
