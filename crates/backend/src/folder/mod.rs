mod filesystem;
mod folder;

pub use filesystem::DiscFolder;
use folder::Folder as GenericFolder;

use crate::Error;
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    events::{EventRecord, ReadEvent, WriteEvent},
    SecretId, VaultCommit, VaultFlags, VaultId,
};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    GateKeeper, Vault, VaultMeta,
};
use std::{borrow::Cow, sync::Arc};
use tokio::sync::RwLock;

use crate::Result;

/// Folder combines a gatekeeper and an event log.
pub enum Folder {
    /// Folder stored on disc.
    FileSystem(DiscFolder),
}

impl Folder {
    /// Folder identifier.
    pub fn id(&self) -> &VaultId {
        todo!();
    }

    /// GateKeeper for this folder.
    pub fn vault(&self) -> &Vault {
        self.keeper().vault()
    }

    /// Gate keeper for this folder.
    pub fn keeper(&self) -> &GateKeeper<Error> {
        todo!();
    }

    /// Mutable gate keeper for this folder.
    pub fn keeper_mut(&mut self) -> &mut GateKeeper<Error> {
        todo!();
    }

    /// Clone of the event log.
    pub fn event_log<L>(&self) -> Arc<RwLock<L>> {
        todo!();
    }

    /// Unlock using the folder access key.
    pub async fn unlock(&mut self, key: &AccessKey) -> Result<VaultMeta> {
        todo!();
    }

    /// Lock the folder.
    pub fn lock(&mut self) {
        todo!();
    }

    /// Create a secret.
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        todo!();
    }

    /// Read the encrypted contents of a secret.
    pub async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> Result<(Option<Cow<'_, VaultCommit>>, ReadEvent)> {
        todo!();
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    /// Delete a secret and it's meta data.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        todo!();
    }

    /// Set the name of the folder.
    pub async fn rename_folder(
        &mut self,
        name: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /// Set the folder flags.
    pub async fn update_folder_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /// Description of this folder.
    pub async fn description(&self) -> Result<String> {
        todo!();
    }

    /// Set the description of this folder.
    pub async fn set_description(
        &mut self,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        todo!();
    }

    /// Set the folder meta data.
    pub async fn set_meta(&mut self, meta: &VaultMeta) -> Result<WriteEvent> {
        todo!();
    }

    /// Folder commit state.
    pub async fn commit_state(&self) -> Result<CommitState> {
        todo!();
    }

    /// Folder root commit hash.
    pub async fn root_hash(&self) -> Result<CommitHash> {
        todo!();
    }

    /// Apply events to the event log.
    pub async fn apply(&mut self, events: Vec<&WriteEvent>) -> Result<()> {
        todo!();
    }

    /// Apply event records to the event log.
    pub async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        todo!();
    }

    /// Clear events from the event log.
    pub async fn clear(&mut self) -> Result<()> {
        todo!();
    }
}
