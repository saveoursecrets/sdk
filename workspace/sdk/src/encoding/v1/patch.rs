//! Patch represents a changeset of events to apply to a vault.
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use crate::{
    constants::PATCH_IDENTITY, events::SyncEvent, formats::FileIdentity,
    patch::Patch,
};

use std::io::{Read, Seek, Write};

impl Patch<'_> {
    fn encode_row<W: Write + Seek>(
        writer: &mut BinaryWriter<W>,
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

    fn decode_row<'a, R: Read + Seek>(
        reader: &mut BinaryReader<R>,
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
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(PATCH_IDENTITY)?;
        for event in self.0.iter() {
            Patch::encode_row(writer, event)?;
        }
        Ok(())
    }
}

impl Decode for Patch<'_> {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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
