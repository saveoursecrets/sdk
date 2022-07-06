//! Patch represents a changeset of events to apply to a vault.
use serde_binary::{
    binary_rw::{BinaryWriter, Endian, FileStream, OpenType, SeekStream},
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
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
    FileIdentity, Result,
};

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Debug, Default)]
pub struct Patch<'a>(pub Vec<SyncEvent<'a>>);

impl Encode for Patch<'_> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&PATCH_IDENTITY)?;
        ser.writer.write_u32(self.0.len() as u32)?;
        for event in self.0.iter() {
            event.encode(&mut *ser)?;
        }
        Ok(())
    }
}

impl Decode for Patch<'_> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        FileIdentity::read_identity(de, &PATCH_IDENTITY)
            .map_err(|e| BinaryError::Boxed(Box::from(e)))?;
        let length = de.reader.read_u32()?;
        for _ in 0..length {
            let mut event: SyncEvent<'static> = Default::default();
            event.decode(&mut *de)?;
            self.0.push(event);
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
        mut events: Vec<SyncEvent<'a>>,
    ) -> Result<Patch<'a>> {
        let len = self.file_path.metadata()?.len() as usize;

        // Load any existing events in to memory
        let mut all_events = if len > PATCH_IDENTITY.len() {
            let patch = self.read()?;
            patch.0
        } else {
            vec![]
        };

        // Append the incoming events to the file
        let mut events_buffer = Vec::new();
        for event in events.iter() {
            let event_buffer = encode(event)?;
            events_buffer.extend_from_slice(&event_buffer);
        }
        self.file.write_all(&events_buffer)?;

        // Append the given events on to any existing events
        // so we can return a new patch to the caller
        all_events.append(&mut events);

        // Write out the new length
        self.write_events_len(all_events.len() as u32)?;

        Ok(Patch(all_events))
    }

    fn write_events_len(&self, length: u32) -> Result<()> {
        let mut stream =
            FileStream::new(&self.file_path, OpenType::ReadWrite)?;
        let mut writer = BinaryWriter::new(&mut stream, Endian::Big);
        writer.seek(PATCH_IDENTITY.len())?;
        writer.write_u32(length)?;
        Ok(())
    }

    /// Read a patch from the file on disc.
    fn read(&self) -> Result<Patch<'static>> {
        let buffer = std::fs::read(&self.file_path)?;
        let patch: Patch = decode(&buffer)?;
        Ok(patch)
    }

    /// Determine if the patch file has some events data.
    pub fn has_events(&self) -> Result<bool> {
        Ok(self.file_path.metadata()?.len() > 8)
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
        let (encryption_key, _) = mock_encryption_key()?;
        let (_, _, _, _, mock_event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;

        // Empty patch file is 8 bytes
        assert_eq!(8, temp.path().metadata()?.len());

        let events = vec![mock_event.clone()];

        let patch = patch_file.append(events)?;
        let new_len = temp.path().metadata()?.len();
        assert!(new_len > 8);
        assert_eq!(1, patch.0.len());

        let more_events = vec![mock_event.clone()];
        let next_patch = patch_file.append(more_events)?;
        let more_len = temp.path().metadata()?.len();
        assert!(more_len > new_len);
        assert_eq!(2, next_patch.0.len());

        let disc_patch = patch_file.read()?;
        assert_eq!(2, disc_patch.0.len());

        // Truncate the file
        let drain_patch = patch_file.drain()?;
        assert_eq!(8, temp.path().metadata()?.len());

        assert_eq!(2, drain_patch.0.len());

        Ok(())
    }
}
