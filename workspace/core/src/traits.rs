//! Common traits.
use crate::Result;
use binary_rw::{BinaryReader, BinaryWriter};

/// Trait for encoding to binary.
pub trait Encode {
    /// Encode self into the binary writer.
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()>;
}

/// Trait for decoding from binary.
pub trait Decode {
    /// Decode from the binary reader into self.
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()>;
}
