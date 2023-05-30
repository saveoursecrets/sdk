//! Patch represents a changeset of events to apply to a vault.
use crate::{
    constants::PATCH_IDENTITY, events::WriteEvent, formats::FileIdentity,
    patch::Patch,
};

use tokio::io::{AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWriteExt};

use async_trait::async_trait;
use binary_stream::{
    tokio::{BinaryReader, BinaryWriter, Decode, Encode},
    BinaryError, BinaryResult,
};

impl Patch<'_> {
    async fn encode_row<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        writer: &mut BinaryWriter<W>,
        event: &WriteEvent<'_>,
    ) -> BinaryResult<()> {
        // Set up the leading row length
        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        // Encode the event data for the row
        event.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(row_pos).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    async fn decode_row<'a, R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<WriteEvent<'a>> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let mut event: WriteEvent<'_> = Default::default();
        event.decode(&mut *reader).await?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32().await?;
        Ok(event)
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Patch<'_> {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.0.iter() {
            Patch::encode_row(writer, event).await?;
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Patch<'_> {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .await
            .map_err(|e| BinaryError::Boxed(Box::from(e)))?;
        let mut pos = reader.tell().await?;
        let len = reader.len().await?;
        while pos < len {
            let event = Patch::decode_row(reader).await?;
            self.0.push(event);
            pos = reader.tell().await?;
        }
        Ok(())
    }
}
