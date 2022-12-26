//! Patch represents a changeset of events to apply to a vault.

use std::path::Path;

use crate::{events::SyncEvent, Result};

use super::{Patch, PatchProvider};

/// Memory based collection of patch events.
#[derive(Default)]
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
        self.read()
    }

    fn count_events(&self) -> Result<usize> {
        Ok(self.records.len())
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;
    use anyhow::Result;

    #[test]
    fn patch_memory() -> Result<()> {
        let mut patch_mem: PatchMemory = Default::default();

        let mut vault = mock_vault();
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, _, _, _, mock_event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;

        let events = vec![mock_event.clone()];

        let patch = patch_mem.append(events)?;
        assert_eq!(1, patch.0.len());
        assert!(patch_mem.has_events()?);

        let more_events = vec![mock_event.clone()];
        let next_patch = patch_mem.append(more_events)?;
        assert_eq!(2, next_patch.0.len());
        assert_eq!(2, patch_mem.count_events()?);

        let disc_patch = patch_mem.read()?;
        assert_eq!(2, disc_patch.0.len());

        // Truncate the file
        let drain_patch = patch_mem.drain()?;
        assert_eq!(2, drain_patch.0.len());
        assert!(!patch_mem.has_events()?);
        assert_eq!(0, patch_mem.count_events()?);

        Ok(())
    }
}
