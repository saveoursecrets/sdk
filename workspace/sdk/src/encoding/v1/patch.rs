//! Patch represents a changeset of events to apply to a vault.
use crate::{
    constants::PATCH_IDENTITY, encoding::encoding_error, events::WriteEvent,
    formats::FileIdentity, patch::Patch,
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Result, SeekFrom};

impl Patch<'_> {
    async fn encode_row<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        writer: &mut BinaryWriter<W>,
        event: &WriteEvent<'_>,
    ) -> Result<()> {
        // Set up the leading row length
        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        // Encodable the event data for the row
        event.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.stream_position().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(SeekFrom::Start(row_pos)).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    async fn decode_row<'a, R: AsyncRead + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
    ) -> Result<WriteEvent<'a>> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let mut event: WriteEvent<'_> = Default::default();
        event.decode(&mut *reader).await?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32().await?;
        Ok(event)
    }
}

#[async_trait]
impl Encodable for Patch<'_> {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.0.iter() {
            Patch::encode_row(writer, event).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Patch<'_> {
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
            let event = Patch::decode_row(reader).await?;
            self.0.push(event);
            pos = reader.stream_position().await?;
        }
        Ok(())
    }
}
