//! Patch represents a changeset of events to apply to a vault.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};

use crate::{
    events::SyncEvent,
    file_identity::{FileIdentity, PATCH_IDENTITY},
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
