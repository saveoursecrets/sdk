//! Patch represents a changeset of events to apply to a vault.
use std::{io::SeekFrom, path::Path};

use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{
    commit::CommitHash,
    constants::PATCH_IDENTITY,
    decode, encode,
    events::{EventLogFile, WriteEvent},
    formats::{patch_stream, EventLogFileStream},
    vfs::{self, OpenOptions},
    Result,
};

use super::Patch;

/// Caches a collection of events on disc which can be used
/// by clients to store changes that have not yet been applied
/// to a remote server.
pub struct PatchFile {
    log_file: EventLogFile,
}

impl PatchFile {
    /// Create a new patch cache provider.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            log_file: EventLogFile::new_patch(path).await?,
        })
    }

    /// Read a patch from the file on disc.
    pub(crate) async fn read(&self) -> Result<Patch> {
        let buffer = vfs::read(&self.log_file.file_path).await?;
        let patch: Patch = decode(&buffer).await?;
        Ok(patch)
    }

    /// Get an iterator for the patch file.
    pub async fn iter(&self) -> Result<EventLogFileStream> {
        patch_stream(&self.log_file.file_path).await
    }

    /// Append some events to this patch cache.
    ///
    /// Returns a collection of events; if this patch cache was empty
    /// beforehand the collection equals the passed events otherwise
    /// it will be any existing events loaded from disc with the given
    /// events appended.
    pub async fn append<'a>(
        &mut self,
        events: Vec<WriteEvent<'a>>,
        last_commit: Option<CommitHash>,
    ) -> Result<Patch> {
        // Load any existing events in to memory
        let mut all_events = if self.has_events().await? {
            let patch = self.read().await?;
            patch.0
        } else {
            vec![]
        };

        let mut last_commit_hash = last_commit;
        let mut records = Vec::new();
        for event in &events {
            let (commit, record) =
                self.log_file.encode_event(event, last_commit_hash).await?;
            records.push(record);
            last_commit_hash = Some(commit);
        }

        // In-memory records for the patch
        let append_patch = Patch(records);

        // Append the incoming events to the file
        self.log_file.apply(events, None).await?;

        // Append the given events on to any existing events
        // so we can return a new patch to the caller that contains
        // all the outstanding events
        let mut events = append_patch.0;
        all_events.append(&mut events);

        Ok(Patch(all_events))
    }

    /// Count the number of events in the patch cache.
    pub async fn count_events(&self) -> Result<usize> {
        let mut count = 0;
        let mut it = self.iter().await?;
        while let Some(_) = it.next_entry().await? {
            count += 1;
        }
        Ok(count)
    }

    /// Determine if the patch cache has any events.
    pub async fn has_events(&self) -> Result<bool> {
        Ok(self.log_file.file.metadata().await?.len() as usize
            > PATCH_IDENTITY.len())
    }

    /// Drain all events from the patch backing storage.
    pub async fn drain(&mut self) -> Result<Patch> {
        let patch = self.read().await?;
        self.truncate().await?;
        Ok(patch)
    }

    /// Truncate the patch backing storage to an empty list.
    ///
    /// This should be called when a client has successfully
    /// applied a patch to the remote and local event log files to
    /// remove any pending events.
    pub async fn truncate(&mut self) -> Result<()> {
        // Workaround for set_len(0) failing with "Access Denied" on Windows
        // SEE: https://github.com/rust-lang/rust/issues/105437
        let _ = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.log_file.file_path)
            .await;
        self.log_file.file.seek(SeekFrom::Start(0)).await?;
        let patch: Patch = Default::default();
        let buffer = encode(&patch).await?;
        self.log_file.file.write_all(&buffer).await?;
        self.log_file.file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test_utils::*, vault::VaultBuilder, vfs};
    use anyhow::Result;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn patch_file() -> Result<()> {
        let temp = NamedTempFile::new()?;
        let mut patch_file = PatchFile::new(temp.path()).await?;

        let (encryption_key, _, passphrase) = mock_encryption_key()?;
        let mut vault =
            VaultBuilder::new().password(passphrase, None).await?;

        let (_, _, _, _, mock_event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")
                .await?;

        // Empty patch file is 4 bytes
        assert_eq!(4, vfs::metadata(temp.path()).await?.len());

        let events = vec![mock_event.clone()];
        let patch = patch_file.append(events, None).await?;

        let new_len = vfs::metadata(temp.path()).await?.len();
        assert!(new_len > 4);
        assert_eq!(1, patch.0.len());
        assert!(patch_file.has_events().await?);

        let more_events = vec![mock_event.clone()];
        let next_patch = patch_file.append(more_events, None).await?;
        let more_len = vfs::metadata(temp.path()).await?.len();
        assert!(more_len > new_len);
        assert_eq!(2, next_patch.0.len());
        assert_eq!(2, patch_file.count_events().await?);

        let disc_patch = patch_file.read().await?;
        assert_eq!(2, disc_patch.0.len());

        // Truncate the file
        let drain_patch = patch_file.drain().await?;
        assert_eq!(4, vfs::metadata(temp.path()).await?.len());

        assert_eq!(2, drain_patch.0.len());
        assert!(!patch_file.has_events().await?);
        assert_eq!(0, patch_file.count_events().await?);

        Ok(())
    }
}
