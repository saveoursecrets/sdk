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
    iter::{patch_iter, FileIterator, FileRecord},
    FileIdentity, Result,
};

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Debug, Default)]
pub struct Patch<'a>(pub Vec<SyncEvent<'a>>);

impl Patch<'_> {
    fn encode_row(
        writer: &mut BinaryWriter,
        event: &SyncEvent<'_>,
    ) -> BinaryResult<()> {
        // Set up the leading row length
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        // Encode the event data for the row
        event.encode(&mut *writer)?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32)?;

        Ok(())
    }

    fn decode_row<'a>(
        reader: &mut BinaryReader,
    ) -> BinaryResult<SyncEvent<'a>> {
        // Read in the row length
        let _ = reader.read_u32()?;

        let mut event: SyncEvent<'_> = Default::default();
        event.decode(&mut *reader)?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32()?;
        Ok(event)
    }
}

impl Encode for Patch<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&PATCH_IDENTITY)?;
        for event in self.0.iter() {
            Patch::encode_row(writer, event)?;
        }
        Ok(())
    }
}

impl Decode for Patch<'_> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .map_err(|e| BinaryError::Boxed(Box::from(e)))?;
        let mut pos = reader.tell()?;
        let len = reader.len()?;
        while pos < len {
            let event = Patch::decode_row(reader)?;
            self.0.push(event);
            pos = reader.tell()?;
        }
        Ok(())
    }
}

/// Caches a collection of events on disc which can be used
/// by clients to store changes that have not yet been applied
/// to a remote server.
pub struct PatchFile {
    file: File,
    file_path: PathBuf,
}

impl PatchFile {
    /// Create a new patch file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
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

    /// The file extension for patch files.
    pub fn extension() -> &'static str {
        PATCH_EXT
    }

    /// Append some events to this patch file.
    ///
    /// Returns a collection of events; if this patch file was empty
    /// beforehand the collection equals the passed events otherwise
    /// it will be any existing events loaded from disc with the given
    /// events appended.
    pub fn append<'a>(
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

    /// Read a patch from the file on disc.
    fn read(&self) -> Result<Patch<'static>> {
        let buffer = std::fs::read(&self.file_path)?;
        let patch: Patch = decode(&buffer)?;
        Ok(patch)
    }

    /// Get an iterator for the patch file.
    pub fn iter(&self) -> Result<FileIterator<FileRecord>> {
        patch_iter(&self.file_path)
    }

    /// Count the number of events in the patch file.
    pub fn count_events(&self) -> Result<usize> {
        Ok(self.iter()?.count())
    }

    /// Determine if the patch file has some events data.
    pub fn has_events(&self) -> Result<bool> {
        Ok(self.file_path.metadata()?.len() as usize > PATCH_IDENTITY.len())
    }

    /// Drain all events from the patch file on disc.
    pub fn drain(&mut self) -> Result<Patch<'static>> {
        let patch = self.read()?;
        self.truncate()?;
        Ok(patch)
    }

    /// Truncate the file to an empty patch list.
    ///
    /// This should be called when a client has successfully
    /// applied a patch to the remote and local WAL files to
    /// remove any pending events.
    pub fn truncate(&mut self) -> Result<()> {
        self.file.set_len(0)?;
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
