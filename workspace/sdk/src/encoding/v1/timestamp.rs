use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use std::io::{Read, Seek, Write};

use time::{Duration, OffsetDateTime};

use crate::Timestamp;

impl Encode for Timestamp {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        let seconds = self.0.unix_timestamp();
        let nanos = self.0.nanosecond();
        writer.write_i64(seconds)?;
        writer.write_u32(nanos)?;
        Ok(())
    }
}

impl Decode for Timestamp {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let seconds = reader.read_i64()?;
        let nanos = reader.read_u32()?;

        self.0 = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(Box::from)?
            + Duration::nanoseconds(nanos as i64);
        Ok(())
    }
}
