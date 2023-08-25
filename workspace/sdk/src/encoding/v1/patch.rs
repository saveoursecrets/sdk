//! Patch represents a changeset of events to apply to a vault.
use crate::{
    constants::PATCH_IDENTITY,
    encoding::encoding_error,
    events::EventRecord,
    formats::{EventLogFileRecord, FileIdentity},
    patch::Patch,
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Result, SeekFrom};

#[async_trait]
impl Encodable for Patch {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.0.iter() {
            event.encode(writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Patch {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .await
            .map_err(encoding_error)?;
        let mut pos = reader.stream_position().await?;
        let len = reader.len().await?;
        while pos < len {
            let mut event: EventRecord = Default::default();
            event.decode(reader).await?;
            self.0.push(event);
            pos = reader.stream_position().await?;
        }
        Ok(())
    }
}
