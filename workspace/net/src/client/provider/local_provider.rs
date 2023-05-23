//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::SecretString;
use sos_sdk::{
    commit::{
        CommitHash, CommitPair, CommitRelationship, CommitTree, SyncInfo,
        SyncKind,
    },
    constants::VAULT_EXT,
    decode, encode,
    events::{ChangeAction, ChangeNotification, SyncEvent},
    events::{EventLogFile, EventReducer},
    patch::PatchFile,
    storage::StorageDirs,
    vault::{Header, Summary, Vault, VaultId},
    Timestamp,
};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use crate::{
    client::provider::{sync, ProviderState, StorageProvider},
    provider_impl,
};

/// Local storage provider.
pub struct LocalProvider {
    /// State of this storage.
    state: ProviderState,

    /// Directories for file storage.
    ///
    /// For memory based storage the paths will be empty.
    dirs: StorageDirs,

    /// Cache for WAL and patch providers.
    cache: HashMap<VaultId, (EventLogFile, PatchFile)>,
}

impl LocalProvider {
    /// Create new node cache backed by files on disc.
    pub fn new(dirs: StorageDirs) -> Result<LocalProvider> {
        if !dirs.documents_dir().is_dir() {
            return Err(Error::NotDirectory(
                dirs.documents_dir().to_path_buf(),
            ));
        }

        Ok(Self {
            state: ProviderState::new(true),
            cache: Default::default(),
            dirs,
        })
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageProvider for LocalProvider {
    provider_impl!();

    /// Create a new account or vault.
    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<SecretString>,
        _is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase, None)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    async fn import_vault(&mut self, buffer: Vec<u8>) -> Result<Summary> {
        self.create_account_with_buffer(buffer).await
    }

    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary> {
        let vault: Vault = decode(&buffer)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok(summary)
    }

    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)> {
        let actions = sync::handle_change(self, change).await?;
        Ok((false, actions))
    }

    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<()> {
        if self.state().mirror() {
            // Write the vault to disc
            let buffer = encode(vault)?;
            self.write_vault_file(summary, &buffer).await?;
        }

        // Apply events to the WAL
        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        wal.clear()?;
        wal.apply(events, None)?;

        Ok(())
    }

    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let storage = self.dirs().vaults_dir();
        let mut summaries = Vec::new();
        let mut contents = tokio::fs::read_dir(&storage).await?;
        while let Some(entry) = contents.next_entry().await? {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(path)?;
                    if summary.flags().is_system() {
                        continue;
                    }
                    summaries.push(summary);
                }
            }
        }

        self.load_caches(&summaries)?;
        self.state.set_summaries(summaries);
        Ok(self.vaults())
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (wal_file, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_wal, old_size, new_size) = wal_file.compact().await?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        *wal_file = compact_wal;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary, None).await?;

        Ok((old_size, new_size))
    }

    fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault> {
        let wal_file = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        Ok(EventReducer::new().reduce(wal_file)?.build()?)
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;
        Ok(())
    }

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        // Log the WAL event
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        self.patch(summary, vec![event.into_owned()]).await?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }

        Ok(())
    }

    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> Result<()> {
        let (wal, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // FIXME: remove this
        // Store events in a patch file so networking
        // logic can see which events need to be synced
        let _patch = patch_file.append(events.clone())?;

        // Apply events to the WAL file
        wal.apply(events, None)?;

        Ok(())
    }

    async fn pull(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let info = SyncInfo {
            before: (head.clone(), head),
            after: None,
            status: SyncKind::Equal,
        };
        Ok(info)
    }

    async fn push(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let info = SyncInfo {
            before: (head.clone(), head),
            after: None,
            status: SyncKind::Equal,
        };
        Ok(info)
    }

    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(CommitRelationship, Option<usize>)> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let pair = CommitPair {
            local: head.clone(),
            remote: head,
        };
        Ok((CommitRelationship::Equal(pair), None))
    }
}
