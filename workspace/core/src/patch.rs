//! Patch represents a changeset of operations to apply to a vault.
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};

use crate::{file_identity::FileIdentity, operations::Payload};

/// Identity magic bytes (SOSP).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x50];

/// Patch wraps a changeset of operations to apply to a vault.
pub struct Patch<'a>(pub Vec<Payload<'a>>);

impl Encode for Patch<'_> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        ser.writer.write_bytes(&IDENTITY)?;
        ser.writer.write_u32(self.0.len() as u32)?;
        for payload in self.0.iter() {
            payload.encode(&mut *ser)?;
        }
        Ok(())
    }
}

impl Decode for Patch<'_> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        FileIdentity::read_identity(de, &IDENTITY)
            .map_err(|e| BinaryError::Boxed(Box::from(e)))?;

        let length = de.reader.read_u32()?;
        for _ in 0..length {
            let mut payload: Payload = Default::default();
            payload.decode(&mut *de)?;
        }

        Ok(())
    }
}
