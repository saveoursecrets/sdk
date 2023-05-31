//! Patch represents a changeset of events to apply to a vault.
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};

use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{
    constants::{PATCH_EXT, PATCH_IDENTITY},
    decode, encode,
    events::WriteEvent,
    formats::{patch_stream, FileRecord, FileStream},
    vfs::{self, File, OpenOptions},
    Result,
};

use super::Patch;

/// Caches a collection of events on disc which can be used
/// by clients to store changes that have not yet been applied
/// to a remote server.
pub struct PatchFile {
    file: File,
    file_path: PathBuf,
}

impl PatchFile {
    /// Create a new patch cache provider.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(path.as_ref())
            .await?;

        let size = file.metadata().await?.len();
        if size == 0 {
            let patch: Patch = Default::default();
            let buffer = encode(&patch).await?;
            file.write_all(&buffer).await?;
            file.flush().await?;
        }

        Ok(Self { file, file_path })
    }

    /// The file extension for patch files.
    pub fn extension() -> &'static str {
        PATCH_EXT
    }

    /// Read a patch from the file on disc.
    pub(crate) async fn read(&self) -> Result<Patch<'static>> {
        let buffer = vfs::read(&self.file_path).await?;
        let patch: Patch = decode(&buffer).await?;
        Ok(patch)
    }

    /// Get an iterator for the patch file.
    pub async fn iter(&self) -> Result<FileStream<FileRecord, File>> {
        patch_stream(&self.file_path).await
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
    ) -> Result<Patch<'a>> {
        // Load any existing events in to memory
        let mut all_events = if self.has_events().await? {
            let patch = self.read().await?;
            patch.0
        } else {
            vec![]
        };

        // Append the incoming events to the file
        let append_patch = Patch(events);
        let append_buffer = encode(&append_patch).await?;
        let append_buffer = &append_buffer[PATCH_IDENTITY.len()..];
        self.file.write_all(append_buffer).await?;
        self.file.flush().await?;

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
        Ok(self.file.metadata().await?.len() as usize > PATCH_IDENTITY.len())
    }

    /// Drain all events from the patch backing storage.
    pub async fn drain(&mut self) -> Result<Patch<'static>> {
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
            .open(&self.file_path)
            .await;
        self.file.seek(SeekFrom::Start(0)).await?;
        let patch: Patch = Default::default();
        let buffer = encode(&patch).await?;
        self.file.write_all(&buffer).await?;
        self.file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test_utils::*, vfs};
    use anyhow::Result;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn patch_file() -> Result<()> {
        let temp = NamedTempFile::new()?;
        let mut patch_file = PatchFile::new(temp.path()).await?;

        let mut vault = mock_vault();
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, _, _, _, mock_event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")
                .await?;

        // Empty patch file is 4 bytes
        assert_eq!(4, vfs::metadata(temp.path()).await?.len());

        let events = vec![mock_event.clone()];

        let patch = patch_file.append(events).await?;

        let new_len = vfs::metadata(temp.path()).await?.len();
        assert!(new_len > 4);
        assert_eq!(1, patch.0.len());
        assert!(patch_file.has_events().await?);

        let more_events = vec![mock_event.clone()];
        let next_patch = patch_file.append(more_events).await?;
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
