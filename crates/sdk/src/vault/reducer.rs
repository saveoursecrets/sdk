use crate::{
    crypto::AeadPack,
    decode,
    events::{EventLogExt, WriteEvent},
    vault::{secret::SecretId, Vault, VaultCommit, VaultFlags},
    Error, Result,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use indexmap::IndexMap;
use sos_core::commit::CommitHash;

/// Reduce log events to a vault.
#[derive(Default)]
pub struct FolderReducer {
    /// Buffer for the create or last update vault event.
    vault: Option<Vec<u8>>,
    /// Last encountered vault name.
    vault_name: Option<String>,
    /// Last encountered vault flags.
    vault_flags: Option<VaultFlags>,
    /// Last encountered vault meta data.
    vault_meta: Option<AeadPack>,
    /// Map of the reduced secrets.
    secrets: IndexMap<SecretId, VaultCommit>,
    /// Reduce events until a particular commit.
    until_commit: Option<CommitHash>,
}

impl FolderReducer {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new reducer until a commit.
    pub fn new_until_commit(until: CommitHash) -> Self {
        Self {
            until_commit: Some(until),
            ..Default::default()
        }
    }

    /// Split a vault into a truncated vault and a collection
    /// of events that represent the vault content.
    ///
    /// The truncated vault represents the header of the vault and
    /// has no contents.
    pub async fn split(vault: Vault) -> Result<(Vault, Vec<WriteEvent>)> {
        let mut events = Vec::with_capacity(vault.len() + 1);
        let header = vault.header().clone();
        let head: Vault = header.into();

        events.push(head.into_event().await?);
        for (id, entry) in vault {
            events.push(WriteEvent::CreateSecret(id, entry));
        }

        Ok((head, events))
    }

    /// Reduce the events in the given event log.
    pub async fn reduce<T, R, W, D>(
        mut self,
        event_log: &T,
    ) -> Result<FolderReducer>
    where
        T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
        R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
        W: AsyncWrite + AsyncSeek + Unpin + Send + Sync + 'static,
        D: Clone + Send + Sync,
    {
        // TODO: use event_log.stream() !
        //

        let mut it = event_log.iter(false).await?;
        if let Some(log) = it.next().await? {
            let event = event_log.decode_event(&log).await?;

            if let WriteEvent::CreateVault(vault) = event {
                self.vault = Some(vault.clone());

                // If we are only reading until the first commit
                // hash return early.
                if let Some(until) = &self.until_commit {
                    if until.0 == log.commit() {
                        return Ok(self);
                    }
                }

                while let Some(log) = it.next().await? {
                    let event = event_log.decode_event(&log).await?;
                    match event {
                        WriteEvent::CreateVault(_) => {
                            return Err(Error::CreateEventOnlyFirst)
                        }
                        WriteEvent::SetVaultName(name) => {
                            self.vault_name = Some(name);
                        }
                        WriteEvent::SetVaultFlags(flags) => {
                            self.vault_flags = Some(flags);
                        }
                        WriteEvent::SetVaultMeta(meta) => {
                            self.vault_meta = Some(meta);
                        }
                        WriteEvent::CreateSecret(id, entry) => {
                            self.secrets.insert(id, entry);
                        }
                        WriteEvent::UpdateSecret(id, entry) => {
                            self.secrets.insert(id, entry);
                        }
                        WriteEvent::DeleteSecret(id) => {
                            self.secrets.shift_remove(&id);
                        }
                        _ => {}
                    }

                    // If we are reading to a particular commit hash
                    // we are done.
                    if let Some(until) = &self.until_commit {
                        if until.0 == log.commit() {
                            break;
                        }
                    }
                }
            } else {
                return Err(Error::CreateEventMustBeFirst);
            }
        }

        Ok(self)
    }

    /// Create a series of new events that represent
    /// a compacted version of the event log.
    ///
    /// This series of events can then be appended to a
    /// new event log to create a compact version with
    /// history pruned.
    ///
    /// Note that compaction is lossy; log record
    /// timestamps are reset.
    ///
    /// The commit tree returned here will be invalid once
    /// the new series of events have been applied so callers
    /// must generate a new commit tree once the new event log has
    /// been created.
    pub async fn compact(self) -> Result<Vec<WriteEvent>> {
        if let Some(vault) = self.vault {
            let mut events = Vec::new();

            let mut vault: Vault = decode(&vault).await?;
            if let Some(name) = self.vault_name {
                vault.set_name(name);
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(Some(meta));
            }

            events.push(vault.into_event().await?);
            for (id, entry) in self.secrets {
                events.push(WriteEvent::CreateSecret(id, entry));
            }
            Ok(events)
        } else {
            Ok(Vec::new())
        }
    }

    /// Consume this reducer and build a vault.
    pub async fn build(self, include_secrets: bool) -> Result<Vault> {
        if let Some(vault) = self.vault {
            let mut vault: Vault = decode(&vault).await?;
            if let Some(name) = self.vault_name {
                vault.set_name(name);
            }

            if let Some(flags) = self.vault_flags {
                *vault.flags_mut() = flags;
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(Some(meta));
            }

            if include_secrets {
                if !vault.is_empty() {
                    tracing::warn!(
                        "reducing into a vault with existing entries"
                    );
                }

                for (id, entry) in self.secrets {
                    vault.insert_entry(id, entry);
                }
            }
            Ok(vault)
        } else {
            Ok(Default::default())
        }
    }
}
