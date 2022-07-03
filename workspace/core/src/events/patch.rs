//! Patch represents a changeset of events to apply to a vault.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
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
            let mut event: SyncEvent = Default::default();
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
            file.write_all(&PATCH_IDENTITY)?;
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
    ) -> Result<Vec<SyncEvent<'a>>> {
        let len = self.file_path.metadata()?.len() as usize;

        // Load any existing events in to memory
        let mut all_events = if len > PATCH_IDENTITY.len() {
            let buffer = std::fs::read(&self.file_path)?;
            let patch: Patch = decode(&buffer)?;
            patch.0
        } else {
            vec![]
        };

        // Append the incoming events to the patch file
        let patch = Patch(events.clone());
        let patch_buffer = encode(&patch)?;
        let patch_bytes = &patch_buffer[PATCH_IDENTITY.len()..];
        self.file.write_all(patch_bytes)?;

        // Append the given events on to any existing events
        all_events.append(&mut events);

        Ok(all_events)
    }

    /// Truncate the file to the identity bytes only.
    ///
    /// This should be called when a client has successfully
    /// applied a patch to the remote and local WAL files to
    /// remove any pending events.
    pub fn truncate(&mut self) -> Result<()> {
        self.file.set_len(PATCH_IDENTITY.len() as u64)?;
        Ok(())
    }
}
