//! Patch represents a changeset of events to apply to a vault.
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::{
    constants::{PATCH_EXT, PATCH_IDENTITY},
    decode, encode,
    events::SyncEvent,
    iter::{patch_iter, FileRecord, ReadStreamIterator},
    Result,
};

use super::{Patch, PatchProvider};

/// Caches a collection of events on disc which can be used
/// by clients to store changes that have not yet been applied
/// to a remote server.
pub struct PatchFile {
    file: File,
    file_path: PathBuf,
}

impl PatchFile {
    /// The file extension for patch files.
    pub fn extension() -> &'static str {
        PATCH_EXT
    }

    /// Read a patch from the file on disc.
    pub(crate) fn read(&self) -> Result<Patch<'static>> {
        let buffer = std::fs::read(&self.file_path)?;
        let patch: Patch = decode(&buffer)?;
        Ok(patch)
    }

    /// Get an iterator for the patch file.
    pub fn iter(&self) -> Result<ReadStreamIterator<FileRecord>> {
        patch_iter(&self.file_path)
    }
}

impl PatchProvider for PatchFile {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();

        if !file_path.exists() {
            File::create(path.as_ref())?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(path.as_ref())?;

        let size = file.metadata()?.len();
        if size == 0 {
            let patch: Patch = Default::default();
            let buffer = encode(&patch)?;
            file.write_all(&buffer)?;
        }

        Ok(Self { file, file_path })
    }

    fn append<'a>(
        &mut self,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<Patch<'a>> {
        // Load any existing events in to memory
        let mut all_events = if self.has_events()? {
            let patch = self.read()?;
            patch.0
        } else {
            vec![]
        };

        // Append the incoming events to the file
        let append_patch = Patch(events);
        let append_buffer = encode(&append_patch)?;
        let append_buffer = &append_buffer[PATCH_IDENTITY.len()..];
        self.file.write_all(append_buffer)?;

        // Append the given events on to any existing events
        // so we can return a new patch to the caller that contains
        // all the outstanding events
        let mut events = append_patch.0;
        all_events.append(&mut events);

        Ok(Patch(all_events))
    }

    fn count_events(&self) -> Result<usize> {
        Ok(self.iter()?.count())
    }

    fn has_events(&self) -> Result<bool> {
        Ok(self.file_path.metadata()?.len() as usize > PATCH_IDENTITY.len())
    }

    fn drain(&mut self) -> Result<Patch<'static>> {
        let patch = self.read()?;
        self.truncate()?;
        Ok(patch)
    }

    fn truncate(&mut self) -> Result<()> {
        // Workaround for set_len(0) failing with "Access Denied" on Windows
        // SEE: https://github.com/rust-lang/rust/issues/105437
        let _ = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path);
        self.file.seek(SeekFrom::Start(0))?;
        let patch: Patch = Default::default();
        let buffer = encode(&patch)?;
        self.file.write_all(&buffer)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;
    use anyhow::Result;
    use tempfile::NamedTempFile;

    #[test]
    fn patch_file() -> Result<()> {
        let temp = NamedTempFile::new()?;
        let mut patch_file = PatchFile::new(temp.path())?;

        let mut vault = mock_vault();
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, _, _, _, mock_event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;

        // Empty patch file is 4 bytes
        assert_eq!(4, temp.path().metadata()?.len());

        let events = vec![mock_event.clone()];

        let patch = patch_file.append(events)?;

        let new_len = temp.path().metadata()?.len();
        assert!(new_len > 4);
        assert_eq!(1, patch.0.len());
        assert!(patch_file.has_events()?);

        let more_events = vec![mock_event.clone()];
        let next_patch = patch_file.append(more_events)?;
        let more_len = temp.path().metadata()?.len();
        assert!(more_len > new_len);
        assert_eq!(2, next_patch.0.len());
        assert_eq!(2, patch_file.count_events()?);

        let disc_patch = patch_file.read()?;
        assert_eq!(2, disc_patch.0.len());

        // Truncate the file
        let drain_patch = patch_file.drain()?;
        assert_eq!(4, temp.path().metadata()?.len());

        assert_eq!(2, drain_patch.0.len());
        assert!(!patch_file.has_events()?);
        assert_eq!(0, patch_file.count_events()?);

        Ok(())
    }
}
