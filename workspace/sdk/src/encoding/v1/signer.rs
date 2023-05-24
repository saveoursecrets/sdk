use std::io::{Read, Seek, Write};

use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use crate::signer::ecdsa::BinarySignature;

impl Encode for BinarySignature {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        // 65 byte signature
        let buffer = self.0.to_bytes();
        writer.write_bytes(buffer)?;
        Ok(())
    }
}

impl Decode for BinarySignature {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let buffer: [u8; 65] =
            reader.read_bytes(65)?.as_slice().try_into()?;
        self.0 = buffer.into();
        Ok(())
    }
}
