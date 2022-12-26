//! Patch represents a changeset of events to apply to a vault.
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
    SeekStream,
};

use std::path::Path;

use crate::{
    constants::PATCH_IDENTITY, events::SyncEvent, FileIdentity, Result,
};

#[cfg(not(target_arch = "wasm32"))]
mod file;
#[cfg(not(target_arch = "wasm32"))]
pub use file::PatchFile;

mod memory;
pub use memory::PatchMemory;

/// Trait for types that cache events in a patch.
pub trait PatchProvider {
    /// Create a new patch cache provider.
    fn new<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;

    /// Append some events to this patch cache.
    ///
    /// Returns a collection of events; if this patch cache was empty
    /// beforehand the collection equals the passed events otherwise
    /// it will be any existing events loaded from disc with the given
    /// events appended.
    fn append<'a>(&mut self, events: Vec<SyncEvent<'a>>)
        -> Result<Patch<'a>>;

    /// Count the number of events in the patch cache.
    fn count_events(&self) -> Result<usize>;

    /// Determine if the patch cache has any events.
    fn has_events(&self) -> Result<bool>;

    /// Drain all events from the patch backing storage.
    fn drain(&mut self) -> Result<Patch<'static>>;

    /// Truncate the patch backing storage to an empty list.
    ///
    /// This should be called when a client has successfully
    /// applied a patch to the remote and local WAL files to
    /// remove any pending events.
    fn truncate(&mut self) -> Result<()>;
}

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch<'a>(pub Vec<SyncEvent<'a>>);

impl Patch<'_> {
    /// Convert all events encapsulated by this patch into owned variants.
    pub fn into_owned(self) -> Patch<'static> {
        let events = self
            .0
            .into_iter()
            .map(|e| e.into_owned())
            .collect::<Vec<_>>();
        Patch(events)
    }

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
        writer.write_bytes(PATCH_IDENTITY)?;
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
