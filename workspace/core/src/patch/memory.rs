//! Patch represents a changeset of events to apply to a vault.
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
    SeekStream,
};

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
    FileIdentity, Result,
};

use super::{Patch, PatchProvider};

/// Memory based collection of patch events.
pub struct PatchMemory<'e> {
    records: Vec<SyncEvent<'e>>,
}

impl PatchMemory<'_> {
    fn read(&self) -> Result<Patch<'static>> {
        let events = self
            .records
            .iter()
            .map(|e| e.clone().into_owned())
            .collect::<Vec<_>>();
        Ok(Patch(events))
    }
}

impl PatchProvider for PatchMemory<'_> {
    fn new<P: AsRef<Path>>(_path: P) -> Result<Self> {
        Ok(Self {
            records: Vec::new(),
        })
    }

    fn append<'a>(
        &mut self,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<Patch<'a>> {
        let mut events = events
            .into_iter()
            .map(|e| e.into_owned())
            .collect::<Vec<_>>();
        self.records.append(&mut events);
        Ok(self.read()?)
    }

    fn count_events(&self) -> Result<usize> {
        Ok(self.records.iter().count())
    }

    fn has_events(&self) -> Result<bool> {
        Ok(!self.records.is_empty())
    }

    fn drain(&mut self) -> Result<Patch<'static>> {
        let patch = self.read()?;
        self.truncate()?;
        Ok(patch)
    }

    fn truncate(&mut self) -> Result<()> {
        self.records = Vec::new();
        Ok(())
    }
}

/*
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
*/
