use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    decode,
    events::{EventLogExt, WriteEvent},
    vault::{secret::SecretId, Vault, VaultCommit, VaultFlags},
    Error, Result,
};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

use indexmap::IndexMap;

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
        W: AsyncWrite + Unpin + Send + Sync + 'static,
        D: Clone + Send + Sync,
    {
        // TODO: use event_log.stream() !
        //

        tracing::info!("FolderReducer::reduce");

        let mut it = event_log.iter(false).await?;
        if let Some(log) = it.next().await? {
            tracing::info!("read event log in reducer: {:#?}", log);
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

mod device {
    use crate::{
        device::TrustedDevice,
        events::{DeviceEvent, DeviceEventLog, EventLogExt},
        Result,
    };
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;

    /// Reduce device events to a collection of devices.
    pub struct DeviceReducer<'a> {
        log: &'a DeviceEventLog,
    }

    impl<'a> DeviceReducer<'a> {
        /// Create a new device reducer.
        pub fn new(log: &'a DeviceEventLog) -> Self {
            Self { log }
        }

        /// Reduce device events to a canonical collection
        /// of trusted devices.
        pub async fn reduce(self) -> Result<IndexSet<TrustedDevice>> {
            let mut devices = IndexSet::new();

            let stream = self.log.stream(false).await;
            pin_mut!(stream);

            while let Some(event) = stream.next().await {
                let (_, event) = event?;

                match event {
                    DeviceEvent::Trust(device) => {
                        devices.insert(device);
                    }
                    DeviceEvent::Revoke(public_key) => {
                        let device = devices
                            .iter()
                            .find(|d| d.public_key() == &public_key)
                            .cloned();
                        if let Some(device) = device {
                            devices.shift_remove(&device);
                        }
                    }
                    _ => {}
                }
            }
            Ok(devices)
        }
    }
}

pub use device::DeviceReducer;

#[cfg(feature = "files")]
mod files {
    use crate::{
        commit::CommitHash,
        events::{EventLogExt, FileEvent, FileEventLog},
        storage::files::ExternalFile,
        Result,
    };
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;

    /// Reduce file events to a collection of external files.
    pub struct FileReducer<'a> {
        log: &'a FileEventLog,
    }

    impl<'a> FileReducer<'a> {
        /// Create a new file reducer.
        pub fn new(log: &'a FileEventLog) -> Self {
            Self { log }
        }

        fn add_file_event(
            &self,
            event: FileEvent,
            files: &mut IndexSet<ExternalFile>,
        ) {
            match event {
                FileEvent::CreateFile(owner, file_name) => {
                    files.insert(ExternalFile::new(owner, file_name));
                }
                FileEvent::MoveFile { name, from, dest } => {
                    let file = ExternalFile::new(from, name);
                    files.shift_remove(&file);
                    files.insert(ExternalFile::new(dest, name));
                }
                FileEvent::DeleteFile(owner, file_name) => {
                    let file = ExternalFile::new(owner, file_name);
                    files.shift_remove(&file);
                }
                _ => {}
            }
        }

        /// Reduce file events to a canonical collection
        /// of external files.
        pub async fn reduce(
            self,
            from: Option<&CommitHash>,
        ) -> Result<IndexSet<ExternalFile>> {
            let mut files: IndexSet<ExternalFile> = IndexSet::new();

            // Reduce from the target commit.
            //
            // When reducing from a target commit we perform
            // a diff as this reads from the tail of the event
            // log which will be faster than scanning when there
            // are lots of file events.
            if let Some(from) = from {
                let patch = self.log.diff_events(Some(from)).await?;
                for record in patch.iter() {
                    let event = record.decode_event::<FileEvent>().await?;
                    self.add_file_event(event, &mut files);
                }
            } else {
                let stream = self.log.stream(false).await;
                pin_mut!(stream);

                while let Some(event) = stream.next().await {
                    let (_, event) = event?;
                    self.add_file_event(event, &mut files);
                }
            }

            Ok(files)
        }
    }
}

#[cfg(feature = "files")]
pub use files::FileReducer;

/*
/// Reduce account events to a collection of folders.
pub struct AccountReducer<'a> {
    log: &'a mut AccountEventLog,
}

impl<'a> AccountReducer<'a> {
    /// Create a new account reducer.
    pub fn new(log: &'a mut AccountEventLog) -> Self {
        Self { log }
    }

    /// Reduce account events to a canonical collection
    /// of folders.
    pub async fn reduce(self) -> Result<HashSet<VaultId>> {
        let mut folders = HashSet::new();
        let events = self.log.diff_records(None).await?;
        for record in events {
            let event = record.decode_event::<AccountEvent>().await?;
            match event {
                AccountEvent::UpdateFolder(id, _)
                | AccountEvent::CreateFolder(id, _) => {
                    folders.insert(id);
                }
                AccountEvent::DeleteFolder(id) => {
                    folders.remove(&id);
                }
                _ => {}
            }
        }
        Ok(folders)
    }
}
*/
